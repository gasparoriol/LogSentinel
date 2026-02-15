mod models;
mod filter;
mod analyzer;
mod watcher;
mod config;
mod dispatcher;
mod ratelimiter;
mod llmprovider;

use tokio::sync::mpsc;
use config::Settings;
use analyzer::Agent;
use filter::LogFilter;
use watcher::LogWatcher;
use models::LogSource;
use dispatcher::{AlertSink, BffSink, EmailSink, FileLoggerSink, Dispatcher};
use std::sync::Arc;
use crate::ratelimiter::AlertRateLimiter;
use crate::llmprovider::{LLMProvider, get_provider};

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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    // Rate limiter initialized after settings load

    if args.daemon {
        let stdout = File::create("/tmp/log_sentinel.out").unwrap();
        let stderr = File::create("/tmp/log_sentinel.err").unwrap();

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

    let settings = Settings::new(args.config.as_deref()).expect("Failed to load settings");
    let log_path = settings.log_path.clone();
    let source = settings.source.clone();
    
    let rate_limiter = Arc::new(AlertRateLimiter::new(&settings.rats));
    let dispatcher_rate_limiter = Arc::clone(&rate_limiter);

    let (tx, mut rx) = mpsc::channel(10_000);

    let provider: Box<dyn LLMProvider> = get_provider(&settings);

    // Agent holds the provider (Box<dyn LLMProvider>) so we wrap Agent in Arc
    let agent = Arc::new(Agent::new(provider));
    let watcher = LogWatcher::new(&log_path);
    let filter = Arc::new(LogFilter::new(settings.filter.clone()));
    
    tokio::spawn(async move {
        loop {
            let watcher = watcher.clone();
            let tx = tx.clone();
            
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

    let multiline_pattern = settings.filter.multiline_pattern.clone();
    let multiline_regex = if let Some(pattern) = &multiline_pattern {
        Some(regex::Regex::new(pattern).expect("Invalid multiline pattern regex"))
    } else {
        None
    };

    let mut log_buffer = String::new();
    let mut last_log_time = tokio::time::Instant::now();
    let log_timeout = tokio::time::Duration::from_millis(300); // Wait 300ms for more lines

    loop {
        tokio::select! {
            Some(line) = rx.recv() => {
                let clean_line = line.trim_end().to_string(); // Keep indentation but trim end

                let is_new_entry = if let Some(re) = &multiline_regex {
                    re.is_match(&clean_line)
                } else {
                    true // If no pattern, every line is new
                };

                if is_new_entry {
                    if !log_buffer.is_empty() {
                         process_log(
                             log_buffer.clone(), 
                             filter.clone(), 
                             agent.clone(), 
                             settings.clone(), 
                             dispatcher_rate_limiter.clone(), 
                             source.clone()
                         ).await;
                         log_buffer.clear();
                    }
                } else {
                    if !log_buffer.is_empty() {
                        log_buffer.push('\n');
                    }
                }
                log_buffer.push_str(&clean_line);
                last_log_time = tokio::time::Instant::now();
            }
            _ = tokio::time::sleep(log_timeout), if !log_buffer.is_empty() => {
                 // Timeout reached, flush buffer
                 process_log(
                     log_buffer.clone(), 
                     filter.clone(), 
                     agent.clone(), 
                     settings.clone(), 
                     dispatcher_rate_limiter.clone(), 
                     source.clone()
                 ).await;
                 log_buffer.clear();
            }
            else => {
                // Channel closed and buffer empty
                break;
            }
        }
    }

    Ok(())
}

async fn process_log(
    line: String,
    filter: Arc<LogFilter>,
    agent: Arc<Agent>,
    settings: Settings,
    dispatcher_rate_limiter: Arc<AlertRateLimiter>,
    source: LogSource,
) {
    tokio::spawn(async move {
        if filter.is_suspicious(&line) {
            println!("Suspicious log detected. Analyzing...");
            
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

