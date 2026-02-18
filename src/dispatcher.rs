use async_trait::async_trait;
use crate::models::SecurityAlert;
use std::fs::OpenOptions;
use std::io::Write;
use serde_json::json;
use std::sync::Arc;
use crate::ratelimiter::AlertRateLimiter;
use tracing::{debug, error, info, warn};


#[async_trait]
pub trait AlertSink: Send + Sync {
    async fn send(&self, alert: &SecurityAlert) -> Result<(), Box<dyn std::error::Error>>;
}

pub struct ConsoleSink;

#[async_trait]
impl AlertSink for ConsoleSink {
    async fn send(&self, alert: &SecurityAlert) -> Result<(), Box<dyn std::error::Error>> {
        info!(severity = %alert.severity, attack_type = %alert.attack_type, "ALERT dispatched");
        Ok(())
    }
}

pub struct BffSink {
    pub url: String,
    pub token: String,
    client: reqwest::Client,
}

impl BffSink {
    pub fn new(url: String, token: String) -> Self {
        Self {
            url,
            token,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl AlertSink for BffSink {
    async fn send(&self, alert: &SecurityAlert) -> Result<(), Box<dyn std::error::Error>> {
        let mut attempts = 0;
        let max_retries = 3;
        
        loop {
            match self.client.post(&self.url)
                .header("X-Agent-Token", &self.token)
                .json(alert)
                .send()
                .await 
            {
                Ok(resp) => {
                    if resp.status().is_success() {
                        debug!(url = %self.url, "BffSink alert sent successfully");
                        return Ok(());
                    } else {
                        warn!(
                            url = %self.url,
                            status = %resp.status(),
                            attempt = attempts + 1,
                            max_retries,
                            "BffSink request failed with non-success status"
                        );
                    }
                },
                Err(e) => warn!(
                    url = %self.url,
                    error = %e,
                    attempt = attempts + 1,
                    max_retries,
                    "BffSink request error"
                ),
            }
            
            attempts += 1;
            if attempts >= max_retries {
                error!(url = %self.url, "BffSink max retries exceeded");
                return Err("Max retries exceeded for BffSink".into());
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(500 * attempts as u64)).await;
        }
    }
}

pub struct SlackSink {
    webhook_url: String,
    client: reqwest::Client,
}

impl SlackSink {
    pub fn new(webhook_url: &str) -> Self {
        Self { 
            webhook_url: webhook_url.to_string(),
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl AlertSink for SlackSink {
    async fn send(&self, alert: &SecurityAlert) -> Result<(), Box<dyn std::error::Error>> {
        let payload = json!({
            "text": format!("ALERT: {:?}", alert),
        });

        let mut attempts = 0;
        let max_retries = 3;

        loop {
            match self.client.post(&self.webhook_url).json(&payload).send().await {
                Ok(resp) => {
                     if resp.status().is_success() {
                        debug!(webhook = %self.webhook_url, "SlackSink alert sent successfully");
                        return Ok(());
                     } else {
                        warn!(
                            webhook = %self.webhook_url,
                            status = %resp.status(),
                            attempt = attempts + 1,
                            max_retries,
                            "SlackSink request failed with non-success status"
                        );
                     }
                },
                Err(e) => warn!(
                    webhook = %self.webhook_url,
                    error = %e,
                    attempt = attempts + 1,
                    max_retries,
                    "SlackSink request error"
                ),
            }

            attempts += 1;
            if attempts >= max_retries {
                error!(webhook = %self.webhook_url, "SlackSink max retries exceeded");
                return Err("Max retries exceeded for SlackSink".into());
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(500 * attempts as u64)).await;
        }
    }
} 
pub struct EmailSink {
    pub recipient: String,
    pub sender: String,
    pub api_url: String,
    client: reqwest::Client, 
}

impl EmailSink {
    pub fn new(recipient: String, sender: String, api_url: String) -> Self {
        Self {
            recipient,
            sender,
            api_url,
            client: reqwest::Client::new(), 
        }
    }
}

#[async_trait]
impl AlertSink for EmailSink {
    async fn send(&self, alert: &SecurityAlert) -> Result<(), Box<dyn std::error::Error>> {
        let payload = json!({
            "to": &self.recipient,
            "subject": format!("Security Alert: {}", alert.severity),
            "text": format!(
                "Detected threat type: {}\nSource: {}\nDescription: {}\nOriginal log: {}",
                alert.attack_type, alert.source_type, alert.description, alert.original_log
            ),
        });

        
        let mut attempts = 0;
        let max_retries = 3;

        loop {
            match self.client.post(&self.api_url)
                .json(&payload)
                .send()
                .await 
            {
                Ok(resp) => {
                    if resp.status().is_success() {
                        debug!(recipient = %self.recipient, "EmailSink alert sent successfully");
                        return Ok(());
                    } else {
                        warn!(
                            recipient = %self.recipient,
                            status = %resp.status(),
                            attempt = attempts + 1,
                            max_retries,
                            "EmailSink request failed with non-success status"
                        );
                    }
                },
                Err(e) => warn!(
                    recipient = %self.recipient,
                    error = %e,
                    attempt = attempts + 1,
                    max_retries,
                    "EmailSink request error"
                ),
            }

            attempts += 1;
            if attempts >= max_retries {
                error!(recipient = %self.recipient, "EmailSink max retries exceeded");
                return Err("Max retries exceeded for EmailSink".into());
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(500 * attempts as u64)).await;
        }
    }
}

pub struct FileLoggerSink {
  pub path: String,
}

impl FileLoggerSink {
  pub fn new(path: &str) -> Self {
    Self { path: path.to_string() }
  }
}

#[async_trait]
impl AlertSink for FileLoggerSink {
    async fn send(&self, alert: &SecurityAlert) -> Result<(), Box<dyn std::error::Error>> {
        let mut file = OpenOptions::new().create(true).append(true).open(&self.path)?;
        let log_line = format!("[{}] {} - {}\n", alert.timestamp, alert.severity, alert.description);
        file.write_all(log_line.as_bytes())?;
        debug!(path = %self.path, "Alert written to log file");
        Ok(())
    }
}

pub struct Dispatcher {
    sinks: Arc<Vec<Box<dyn AlertSink>>>,
    rate_limiter: Arc<AlertRateLimiter>,
}

impl Dispatcher {
    pub fn new(sinks: Arc<Vec<Box<dyn AlertSink>>>, rate_limiter: Arc<AlertRateLimiter>) -> Self {
        Self {
            sinks,
            rate_limiter,
        }
    }

    pub async fn dispatch(&self, alert: &SecurityAlert) -> Result<(), Box<dyn std::error::Error>> {
        let key = &alert.attack_type;

        if self.rate_limiter.check_alert(key) {
            for sink in &*self.sinks {
                if let Err(e) = sink.send(alert).await {
                    error!(error = %e, "Failed to send alert to a destination");
                }
            }
        } else {
            warn!(key = %key, "Alert suppressed by rate limiter");
        }
        Ok(())
    }
}