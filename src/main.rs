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
use std::sync::Arc;

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
    let args = Args::parse();
    // Rate limiter initialized after settings load

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
            Ok(_) => println!("Success, daemonized"),
            Err(e) => eprintln!("Error, {}", e),
        }
    }

    let settings = Settings::new(args.config.as_deref(), args.api_key_file)?;
    let log_path = settings.log_path.clone();
    let source = settings.source.clone();
    
    let rate_limiter = Arc::new(AlertRateLimiter::new(&settings.rats)?);
    let dispatcher_rate_limiter = Arc::clone(&rate_limiter);

    let (tx, rx) = mpsc::channel(10_000);

    let provider: Box<dyn LLMProvider> = get_provider(&settings)?;

    // Agent holds the provider (Box<dyn LLMProvider>) so we wrap Agent in Arc
    let agent = Arc::new(Agent::new(provider));
    let watcher = LogWatcher::new(&log_path);
    let filter = Arc::new(LogFilter::new(settings.filter.clone()));
    
    // Spawn watcher
    let watcher_clone = watcher.clone();
    let tx_clone = tx.clone();
    tokio::spawn(async move {
        loop {
            let watcher = watcher_clone.clone();
            let tx = tx_clone.clone();
            
            let task = tokio::spawn(async move {
                watcher.watch(tx).await
            });

            match task.await {
                Ok(Ok(())) => eprintln!("Watcher exited cleanly. Restarting check in 5s..."),
                Ok(Err(e)) => eprintln!("Watcher failed: {:?}. Restarting in 5s...", e),
                Err(e) => eprintln!("Watcher panicked or was cancelled: {:?}. Restarting in 5s...", e),
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    });

    println!("LogSentinel started. Watching log file: {}", log_path);

    // Orchestrate aggregation and processing
    let aggregator = LogAggregator::new(
        settings.filter.multiline_pattern.clone(),
        300 // 300ms timeout
    );

    let sinks: Arc<Vec<Box<dyn AlertSink>>> = Arc::new(create_sinks(&settings));

    aggregator.run(rx, move |combined_log| {
        let filter = Arc::clone(&filter);
        let agent = Arc::clone(&agent);
        let rate_limiter = Arc::clone(&dispatcher_rate_limiter);
        let source = source.clone();
        let sinks = Arc::clone(&sinks);
        
        async move {
            process_log(combined_log, filter, agent, rate_limiter, source, sinks).await;
        }
    }).await;

    Ok(())
}

async fn process_log(
    line: String,
    filter: Arc<LogFilter>,
    agent: Arc<Agent>,
    dispatcher_rate_limiter: Arc<AlertRateLimiter>,
    source: LogSource,
    sinks: Arc<Vec<Box<dyn AlertSink>>>,
) {
    tokio::spawn(async move {
        if filter.is_suspicious(&line) {
            println!("Suspicious log detected. Analyzing...");

            let dispatcher = Dispatcher::new(sinks, dispatcher_rate_limiter);

            if let Some(alert) = agent.analyze(&line, &source).await {
                println!("[CONFIRMED THREAT]: {}", alert);
                if let Err(e) = dispatcher.dispatch(&alert).await {
                        eprintln!("Error dispatching alert: {}", e);
                }
            } else {
                println!("False positive: The AI says it's normal.");
            }
        }
    });
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

