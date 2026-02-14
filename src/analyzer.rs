use chrono::Utc;
use serde_json::Value;
use crate::models::{LogSource, SecurityAlert};
use crate::llmprovider::LLMProvider;

pub struct Agent {
    provider: Box<dyn LLMProvider>,
}

impl Agent {
    pub fn new(provider: Box<dyn LLMProvider>) -> Self {
        Self { provider }
    }

    pub async fn analyze(&self, line: &str, source: &LogSource) -> Option<SecurityAlert> {
        let result_str = self.provider.analyze(line, source).await.ok()?;

        if result_str.contains("NULL") {
            return None;
        }

        if let Ok(temp_alert) = serde_json::from_str::<Value>(&result_str) {
            return Some(SecurityAlert {
                timestamp: Utc::now().to_rfc3339(),
                source_type: source.as_str().to_string(),
                severity: temp_alert["severity"].as_str().unwrap_or("LOW").to_string(),
                attack_type: temp_alert["attack_type"].as_str().unwrap_or("Unknown").to_string(),
                description: temp_alert["description"].as_str().unwrap_or("").to_string(),
                original_log: line.to_string(),
            });
        }

        None
    }
}