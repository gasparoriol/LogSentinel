mod models;
mod filter;
mod analyzer;
mod watcher;
mod config;
mod dispatcher;

use tokio::sync::mpsc;
use config::Settings;
use models::LogSource;
use analyzer::Agent;
use filter::LogFilter;
use watcher::LogWatcher;
use dispatcher::{AlertSink, BffSink, EmailSink, FileLoggerSink};
use reqwest::Client;


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let settings = Settings::new().expect("Failed to load settings");
    let log_path = settings.log_path;
    let source = settings.source;
    let (tx, mut rx) = mpsc::channel(100);
    let model = settings.server.model;
    let api_url = settings.server.api_url;
    let agent = Agent::new(&model, api_url.as_deref());
    let watcher = LogWatcher::new(&log_path);
    tokio::spawn(async move {
        if let Err(e) = watcher.watch(tx).await {
            eprintln!("Error in the watcher: {:?}", e);
        }
    });

    println!("Universal Observability Agent started. Watching log file: {}", log_path);

    while let Some(line) = rx.recv().await {
        let clean_line = line.trim();
        
        if LogFilter::is_suspicious(clean_line) {
            println!("Suspicious log detected. Analyzing...");
            
            let mut sinks: Vec<Box<dyn AlertSink>> = Vec::new();

            if settings.bff.enabled {
                sinks.push(Box::new(BffSink {
                    url: settings.bff.url.clone(),
                    token: settings.bff.token.clone(),
                }));
            }

            if settings.logger.enabled {
                sinks.push(Box::new(FileLoggerSink {
                    path: settings.logger.path.clone(),
                }));
            }

            if settings.email.enabled {
                sinks.push(Box::new(EmailSink::new(settings.email.recipient.clone(), settings.email.from.clone(), settings.email.api_url.clone())   ));
            }

            if let Some(alert) = agent.analyze(clean_line, &source).await {
                println!("[CONFIRMED THREAT]: {}", alert);
                for sink in &sinks {
                    if let Err(e) = sink.send(&alert).await {
                        eprintln!("Failed to send alert to a destination: {}", e);
                    }
                }
            } else {
                println!("False positive: The AI says it's normal.");
            }
        }
    }

    Ok(())
}