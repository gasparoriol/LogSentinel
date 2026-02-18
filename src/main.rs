use tokio::sync::mpsc;
use log_sentinel::config::Settings;
use log_sentinel::analyzer::Agent;
use log_sentinel::filter::LogFilter;
use log_sentinel::watcher::LogWatcher;
use log_sentinel::models::LogSource;
use log_sentinel::dispatcher::{AlertSink, BffSink, EmailSink, FileLoggerSink, Dispatcher};
use log_sentinel::ratelimiter::AlertRateLimiter;
use log_sentinel::llmprovider::{LLMProvider, get_provider};
use log_sentinel::aggregator::LogAggregator;
use log_sentinel::metrics::REGISTRY;
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

use axum::{routing::get, Router};
use prometheus::{Encoder, TextEncoder};
use clap::Parser;
use daemonize::Daemonize;
use std::fs::File;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    config: Option<String>,

    #[arg(short, long)]
    daemon: bool,

    #[arg(long)]
    api_key_file: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    if args.daemon {
        let stdout = File::create("/tmp/log_sentinel.out")?;
        let stderr = File::create("/tmp/log_sentinel.err")?;

        let daemonize = Daemonize::new()
            .pid_file("/tmp/log_sentinel.pid")
            .chown_pid_file(true)
            .working_directory(".")
            .stdout(stdout)
            .stderr(stderr);

        match daemonize.start() {
            Ok(_) => info!("Process daemonized successfully"),
            Err(e) => error!(error = %e, "Failed to daemonize process"),
        }
    }

    let settings = Settings::new(args.config.as_deref(), args.api_key_file)?;
    let log_path = settings.log_path.clone();
    let source = settings.source.clone();
    
    // Start Metrics Server if enabled
    if settings.metrics.enabled {
        let port = settings.metrics.port;
        tokio::spawn(async move {
            let app = Router::new().route("/metrics", get(|| async {
                let encoder = TextEncoder::new();
                let metric_families = REGISTRY.gather();
                let mut buffer = Vec::new();
                encoder.encode(&metric_families, &mut buffer).unwrap();
                String::from_utf8(buffer).unwrap()
            }));

            let addr = format!("0.0.0.0:{}", port);
            info!(port = %port, "Metrics server listening");
            let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
            axum::serve(listener, app).await.unwrap();
        });
    }

    let rate_limiter = Arc::new(AlertRateLimiter::new(&settings.rats)?);
    let dispatcher_rate_limiter = Arc::clone(&rate_limiter);

    let (tx, rx) = mpsc::channel(10_000);
    let (analysis_tx, mut analysis_rx) = mpsc::channel(1_000);

    let provider: Box<dyn LLMProvider> = get_provider(&settings)?;

    // Agent holds the provider (Box<dyn LLMProvider>) so we wrap Agent in Arc
    let agent = Arc::new(Agent::new(provider));
    let watcher = LogWatcher::new(&log_path);
    let filter = Arc::new(LogFilter::new(settings.filter.clone()));
    
    // Spawn watcher with exponential backoff and retry limit
    let watcher_clone = watcher.clone();
    let tx_clone = tx.clone();
    tokio::spawn(async move {
        const MAX_RETRIES: u32 = 5;
        const BASE_DELAY_SECS: u64 = 5;
        const MAX_DELAY_SECS: u64 = 120;

        let mut consecutive_failures: u32 = 0;

        loop {
            let watcher = watcher_clone.clone();
            let tx = tx_clone.clone();

            let task = tokio::spawn(async move {
                watcher.watch(tx).await
            });

            match task.await {
                Ok(Ok(())) => {
                    // Clean exit: reset failure counter and restart quickly
                    info!("Watcher exited cleanly, restarting in {}s", BASE_DELAY_SECS);
                    consecutive_failures = 0;
                    tokio::time::sleep(tokio::time::Duration::from_secs(BASE_DELAY_SECS)).await;
                }
                Ok(Err(e)) => {
                    consecutive_failures += 1;
                    if consecutive_failures >= MAX_RETRIES {
                        error!(
                            error = ?e,
                            consecutive_failures,
                            "Watcher failed too many times, giving up"
                        );
                        break;
                    }
                    let delay = (BASE_DELAY_SECS * (1 << consecutive_failures)).min(MAX_DELAY_SECS);
                    warn!(
                        error = ?e,
                        attempt = consecutive_failures,
                        max = MAX_RETRIES,
                        delay_secs = delay,
                        "Watcher failed, retrying with backoff"
                    );
                    tokio::time::sleep(tokio::time::Duration::from_secs(delay)).await;
                }
                Err(e) => {
                    consecutive_failures += 1;
                    if consecutive_failures >= MAX_RETRIES {
                        error!(
                            error = ?e,
                            consecutive_failures,
                            "Watcher panicked too many times, giving up"
                        );
                        break;
                    }
                    let delay = (BASE_DELAY_SECS * (1 << consecutive_failures)).min(MAX_DELAY_SECS);
                    error!(
                        error = ?e,
                        attempt = consecutive_failures,
                        max = MAX_RETRIES,
                        delay_secs = delay,
                        "Watcher panicked, retrying with backoff"
                    );
                    tokio::time::sleep(tokio::time::Duration::from_secs(delay)).await;
                }
            }
        }
    });

    info!(log_path = %log_path, "LogSentinel started");

    // Orchestrate aggregation and processing
    let aggregator = LogAggregator::new(
        settings.filter.multiline_pattern.clone(),
        300 // 300ms timeout
    );

    let sinks: Arc<Vec<Box<dyn AlertSink>>> = Arc::new(create_sinks(&settings));

    // Spawn Analysis Batcher
    let agent_batch = Arc::clone(&agent);
    let sinks_batch = Arc::clone(&sinks);
    let rate_limiter_batch = Arc::clone(&dispatcher_rate_limiter);
    let source_batch = source.clone();
    let batch_size = settings.analysis.batch_size;
    let batch_timeout = settings.analysis.batch_timeout_ms;

    tokio::spawn(async move {
        let mut batch = Vec::new();
        let mut last_flush = tokio::time::Instant::now();

        loop {
            let timeout = tokio::time::Duration::from_millis(batch_timeout);
            let sleep = tokio::time::sleep_until(last_flush + timeout);

            tokio::select! {
                Some(log) = analysis_rx.recv() => {
                    batch.push(log);
                    if batch.len() >= batch_size {
                        flush_batch(&mut batch, &agent_batch, &sinks_batch, &rate_limiter_batch, &source_batch).await;
                        last_flush = tokio::time::Instant::now();
                    }
                }
                _ = sleep => {
                    if !batch.is_empty() {
                        flush_batch(&mut batch, &agent_batch, &sinks_batch, &rate_limiter_batch, &source_batch).await;
                    }
                    last_flush = tokio::time::Instant::now();
                }
            }
        }
    });

    aggregator.run(rx, move |combined_log| {
        let filter = Arc::clone(&filter);
        let analysis_tx = analysis_tx.clone();
        
        async move {
            process_log(combined_log, filter, analysis_tx).await;
        }
    }).await;

    Ok(())
}

async fn process_log(
    line: String,
    filter: Arc<LogFilter>,
    analysis_tx: mpsc::Sender<String>,
) {
    if filter.is_suspicious(&line) {
        log_sentinel::metrics::SUSPICIOUS_LOGS.inc();
        info!(line = %line, "Suspicious log detected, queuing for batch analysis");
        let _ = analysis_tx.send(line).await;
    } else {
        debug!("Log line not suspicious, skipping");
    }
}

async fn flush_batch(
    batch: &mut Vec<String>,
    agent: &Arc<Agent>,
    sinks: &Arc<Vec<Box<dyn AlertSink>>>,
    rate_limiter: &Arc<AlertRateLimiter>,
    source: &LogSource,
) {
    let lines_to_analyze = std::mem::take(batch);
    let count = lines_to_analyze.len();
    info!(count, "Flushing analysis batch");
    log_sentinel::metrics::ANALYSIS_BATCHES.inc();

    let start = std::time::Instant::now();
    let alerts = agent.analyze_batch(&lines_to_analyze, source).await;
    let duration = start.elapsed().as_secs_f64();
    log_sentinel::metrics::ANALYSIS_LATENCY.observe(duration);

    if !alerts.is_empty() {
        let dispatcher = Dispatcher::new(Arc::clone(sinks), Arc::clone(rate_limiter));
        for alert in alerts {
            log_sentinel::metrics::CONFIRMED_THREATS.inc();
            info!(
                severity = %alert.severity,
                attack_type = %alert.attack_type,
                "[CONFIRMED THREAT FROM BATCH]"
            );
            if let Err(e) = dispatcher.dispatch(&alert).await {
                error!(error = %e, "Error dispatching alert from batch");
            }
        }
    } else {
        info!("Batch analysis complete: no threats confirmed");
    }
}

fn create_sinks(settings: &Settings) -> Vec<Box<dyn AlertSink>> {
    let mut sinks: Vec<Box<dyn AlertSink>> = Vec::new();

    if settings.bff.enabled {
        sinks.push(Box::new(BffSink::new(
            settings.bff.url.clone(),
            settings.bff.token.clone(),
        )));
    }

    if settings.logger.enabled {
        sinks.push(Box::new(FileLoggerSink {
            path: settings.logger.path.clone(),
        }));
    }

    if settings.email.enabled {
        sinks.push(Box::new(EmailSink::new(settings.email.recipient.clone(), settings.email.from.clone(), settings.email.api_url.clone())   ));
    }

    sinks
}

