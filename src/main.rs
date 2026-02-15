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

    while let Some(line) = rx.recv().await {
        let clean_line = line.trim().to_string();
        
        // Clone Arcs for the background task
        let filter = filter.clone();
        let agent = agent.clone();
        let settings = settings.clone();
        let dispatcher_rate_limiter = dispatcher_rate_limiter.clone();
        let source = source.clone();

        tokio::spawn(async move {
            if filter.is_suspicious(&clean_line) {
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

                if let Some(alert) = agent.analyze(&clean_line, &source).await {
                    println!("[CONFIRMED THREAT]: {}", alert);
                    if let Err(e) = dispatcher.dispatch(&alert).await {
                         eprintln!("Error dispatching alert: {}", e);
                    }
                } else {
                    println!("False positive: The AI says it's normal.");
                }
            } else {
                // Keep this brief or remove if too noisy at high volume
                // println!("Normal log: {}", clean_line);
            }
        });
    }

    Ok(())
}

