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
}