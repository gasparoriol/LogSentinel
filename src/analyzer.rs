use reqwest::Client;
use serde_json::{json, Value};
use chrono::Utc;
use crate::models::{LogSource, SecurityAlert};

pub struct Agent {
  client: Client,
  model: String,
  api_url: String,
}

impl Agent {
  pub fn new(model: &str, api_url: Option<&str>) -> Self {
    Self {
      client: Client::new(),
      model: model.to_string(),
      api_url: api_url
                .unwrap_or("http://localhost:11434/api/generate")
                .to_string(),
    }
  }

  pub async fn analyze(&self, line: &str, source: &LogSource) -> Option<SecurityAlert> {
    let prompt = format!(
      "Analyze this log of {}: \"{}\". If it is a threat, respond ONLY with a JSON object containing these fields: 
      'severity' (LOW, MEDIUM, HIGH, CRITICAL), 
      'attack_type', 
      and 'description'. 
      If it is NOT a threat, respond with the word 'NULL'.",
        source.get_context(),
        line
    );

    let response = self.client.post(&self.api_url)
            .json(&json!({
                "model": &self.model,
                "prompt": prompt,
                "stream": false,
                "format": "json" 
            }))
            .send()
            .await
            .ok()?
            .json::<Value>()
            .await
            .ok()?;

    let content = response["response"].as_str()?;

    if content.contains("NULL") {
        return None;
    }

    if let Ok(temp_alert) = serde_json::from_str::<Value>(content) {
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