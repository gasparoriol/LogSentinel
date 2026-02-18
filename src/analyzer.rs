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

    pub async fn analyze_batch(&self, lines: &[String], source: &LogSource) -> Vec<SecurityAlert> {
        let mut alerts = Vec::new();
        let result_str = match self.provider.analyze_batch(lines, source).await {
            Ok(s) => s,
            Err(_) => return alerts,
        };

        if let Ok(Value::Array(results)) = serde_json::from_str::<Value>(&result_str) {
            for item in results {
                let status = item["status"].as_str().unwrap_or("");
                if status == "NULL" {
                    continue;
                }

                let index = item["index"].as_u64().unwrap_or(0) as usize;
                if index >= lines.len() {
                    continue;
                }

                alerts.push(SecurityAlert {
                    timestamp: Utc::now().to_rfc3339(),
                    source_type: source.as_str().to_string(),
                    severity: item["severity"].as_str().unwrap_or("LOW").to_string(),
                    attack_type: item["attack_type"].as_str().unwrap_or("Unknown").to_string(),
                    description: item["description"].as_str().unwrap_or("").to_string(),
                    original_log: lines[index].clone(),
                });
            }
        }

        alerts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};

    struct MockLLMProvider {
        response: Arc<Mutex<String>>,
    }

    impl MockLLMProvider {
        fn new(response: &str) -> Self {
            Self {
                response: Arc::new(Mutex::new(response.to_string())),
            }
        }
    }

    #[async_trait]
    impl LLMProvider for MockLLMProvider {
        async fn analyze(&self, _log_line: &str, _source: &LogSource) -> Result<String, Box<dyn std::error::Error>> {
            Ok(self.response.lock().unwrap().clone())
        }
        
        async fn analyze_batch(&self, _log_lines: &[String], _source: &LogSource) -> Result<String, Box<dyn std::error::Error>> {
            Ok(self.response.lock().unwrap().clone())
        }

        fn name(&self) -> String {
            "Mock".to_string()
        }
    }

    #[tokio::test]
    async fn test_agent_analyze_threat() {
        let response_json = r#"{"severity": "HIGH", "attack_type": "SQLi", "description": "SQL Injection detected"}"#;
        let provider = Box::new(MockLLMProvider::new(response_json));
        let agent = Agent::new(provider);
        let source = LogSource::Tomcat;
        
        let alert = agent.analyze("SELECT * FROM users", &source).await.unwrap();
        
        assert_eq!(alert.severity, "HIGH");
        assert_eq!(alert.attack_type, "SQLi");
        assert_eq!(alert.description, "SQL Injection detected");
    }

    #[tokio::test]
    async fn test_agent_analyze_non_threat() {
        let provider = Box::new(MockLLMProvider::new("NULL"));
        let agent = Agent::new(provider);
        let source = LogSource::Nginx;
        
        let alert = agent.analyze("GET /index.html", &source).await;
        
        assert!(alert.is_none());
    }

    #[tokio::test]
    async fn test_agent_analyze_malformed_json() {
        let provider = Box::new(MockLLMProvider::new("not a json"));
        let agent = Agent::new(provider);
        let source = LogSource::Dotnet;
        
        let alert = agent.analyze("Something happened", &source).await;
        
        assert!(alert.is_none());
    }
    #[tokio::test]
    async fn test_agent_analyze_batch() {
        let batch_response = r#"[
            {"index": 0, "severity": "HIGH", "attack_type": "SQLi", "description": "Threat 1"},
            {"index": 1, "status": "NULL"},
            {"index": 2, "severity": "MEDIUM", "attack_type": "XSS", "description": "Threat 2"}
        ]"#;
        let provider = Box::new(MockLLMProvider::new(batch_response));
        let agent = Agent::new(provider);
        let logs = vec![
            "SELECT * FROM users".to_string(),
            "GET /normal".to_string(),
            "<script>alert(1)</script>".to_string()
        ];
        
        let alerts = agent.analyze_batch(&logs, &LogSource::Generic).await;
        
        assert_eq!(alerts.len(), 2);
        assert_eq!(alerts[0].attack_type, "SQLi");
        assert_eq!(alerts[0].original_log, logs[0]);
        assert_eq!(alerts[1].attack_type, "XSS");
        assert_eq!(alerts[1].original_log, logs[2]);
    }
}