use async_trait::async_trait;
use crate::models::SecurityAlert;
use std::fs::OpenOptions;
use std::io::Write;
use serde_json::json;


#[async_trait]
pub trait AlertSink: Send + Sync {
    async fn send(&self, alert: &SecurityAlert) -> Result<(), Box<dyn std::error::Error>>;
}

pub struct ConsoleSink;

#[async_trait]
impl AlertSink for ConsoleSink {
    async fn send(&self, alert: &SecurityAlert) -> Result<(), Box<dyn std::error::Error>> {
        println!("ALERT: {:?}", alert);
        Ok(())
    }
}

pub struct BffSink {
    pub url: String,
    pub token: String,
}

#[async_trait]
impl AlertSink for BffSink {
    async fn send(&self, alert: &SecurityAlert) -> Result<(), Box<dyn std::error::Error>> {
        let client = reqwest::Client::new();
        client.post(&self.url)
            .header("X-Agent-Token", &self.token)
            .json(alert)
            .send()
            .await?;
        Ok(())
    }
}

pub struct SlackSink {
    webhook_url: String,
}

impl SlackSink {
    pub fn new(webhook_url: &str) -> Self {
        Self { webhook_url: webhook_url.to_string() }
    }
}

#[async_trait]
impl AlertSink for SlackSink {
    async fn send(&self, alert: &SecurityAlert) -> Result<(), Box<dyn std::error::Error>> {
        let client = reqwest::Client::new();
        let payload = json!({
            "text": format!("ALERT: {:?}", alert),
        });
        client.post(&self.webhook_url).json(&payload).send().await?;
        Ok(())
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

        
        self.client.post(&self.api_url)
            .json(&payload)
            .send()
            .await?;

        Ok(())
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
        Ok(())
    }
}   
    