use async_trait::async_trait;
use reqwest::Client;
use serde_json::{json, Value};
use secrecy::{SecretString, ExposeSecret};
use crate::models::LogSource;
use crate::config::Settings;

#[async_trait]
pub trait LLMProvider: Send + Sync {
    async fn analyze(&self, log_line: &str, source: &LogSource) -> Result<String, Box<dyn std::error::Error>>;

    fn name(&self) -> String;
}

pub struct OllamaProvider {
    client: Client,
    model: String,
    api_url: String,
}

impl OllamaProvider {
    pub fn new(model: &str, api_url: &str) -> Self {
        Self {
            client: Client::new(),
            model: model.to_string(),
            api_url: api_url.to_string(),
        }
    }
}

#[async_trait]
impl LLMProvider for OllamaProvider {
    async fn analyze(&self, log_line: &str, source: &LogSource) -> Result<String, Box<dyn std::error::Error>> {
        let prompt = format!(
            "Analyze this log of {}: \"{}\". If it is a threat, respond ONLY with a JSON object containing these fields: 
            'severity' (LOW, MEDIUM, HIGH, CRITICAL), 
            'attack_type', 
            and 'description'. 
            If it is NOT a threat, respond with the word 'NULL'.",
            source.get_context(),
            log_line
        );

        let response = self.client.post(&self.api_url)
            .json(&json!({
                "model": &self.model,
                "prompt": prompt,
                "stream": false,
                "format": "json" 
            }))
            .send()
            .await?
            .json::<Value>()
            .await?;

        let content = response["response"].as_str().ok_or("No response field")?;

        if content.contains("NULL") {
            return Ok("NULL".to_string());
        }

        if serde_json::from_str::<Value>(content).is_ok() {
            return Ok(content.to_string());
        }

        Ok("NULL".to_string())
    }

    fn name(&self) -> String {
        "Ollama".to_string()
    }
}

pub struct OpenAiProvider {
    client: Client,
    api_key: SecretString, 
    model: String,
    api_url: String, // Allow custom URL for OpenAI compatible APIs if needed, or default to standard
}

impl OpenAiProvider {
    pub fn new(api_key: SecretString, model: &str, api_url: Option<String>) -> Self {
        Self { 
            client: Client::new(),
            api_key, 
            model: model.to_string(),
            api_url: api_url.unwrap_or("https://api.openai.com/v1/chat/completions".to_string())
        }
    }
}

#[async_trait]
impl LLMProvider for OpenAiProvider {
    async fn analyze(&self, log_line: &str, source: &LogSource) -> Result<String, Box<dyn std::error::Error>> {
      let prompt = format!(
        "Analyze this log of {}: \"{}\". If it is a threat, respond ONLY with a JSON object containing these fields: 
        'severity' (LOW, MEDIUM, HIGH, CRITICAL), 
        'attack_type', 
        and 'description'. 
        If it is NOT a threat, respond with the word 'NULL'.",
          source.get_context(),
          log_line
      );

      let response = self.client.post(&self.api_url)
              .header("Authorization", format!("Bearer {}", self.api_key.expose_secret()))
              .json(&json!({
                  "model": &self.model,
                  "messages": [
                      {"role": "system", "content": "You are a cybersecurity expert. Response in JSON format only."},
                      {"role": "user", "content": prompt}
                  ],
                  "temperature": 0
              }))
              .send()
              .await?
              .json::<Value>()
              .await?;

      // OpenAI response structure is different
      let content = response["choices"][0]["message"]["content"].as_str().ok_or("No content in response")?;

      if content.contains("NULL") {
          return Ok("NULL".to_string());
      }

      // Cleanup code blocks if present (markdown json)
      let cleaned_content = content.trim().trim_start_matches("```json").trim_start_matches("```").trim_end_matches("```").trim();

      if serde_json::from_str::<Value>(cleaned_content).is_ok() {
              return Ok(cleaned_content.to_string());
      }

      Ok("NULL".to_string())
    }

    fn name(&self) -> String {
        "OpenAI".to_string()
    }
}

pub struct GeminiProvider {
    client: Client,
    api_key: SecretString,
    model: String,
    api_url: String,
}

impl GeminiProvider {
    pub fn new(api_key: SecretString, model: &str, api_url: Option<String>) -> Self {
        Self {
            client: Client::new(),
            api_key,
            model: model.to_string(),
            api_url: api_url.unwrap_or("https://generativelanguage.googleapis.com/v1beta/models".to_string()),
        }
    }
}

#[async_trait]
impl LLMProvider for GeminiProvider {
    async fn analyze(&self, log_line: &str, source: &LogSource) -> Result<String, Box<dyn std::error::Error>> {
        let prompt = format!(
            "Analyze this log of {}: \"{}\". If it is a threat, respond ONLY with a JSON object containing these fields: 
            'severity' (LOW, MEDIUM, HIGH, CRITICAL), 
            'attack_type', 
            and 'description'. 
            If it is NOT a threat, respond with the word 'NULL'.",
            source.get_context(),
            log_line
        );

        let url = format!("{}/{}:generateContent?key={}", self.api_url, self.model, self.api_key.expose_secret());

        let response = self.client.post(&url)
            .json(&json!({
                "contents": [{
                    "parts": [{
                        "text": prompt
                    }]
                }]
            }))
            .send()
            .await?
            .json::<Value>()
            .await?;

        // Gemini response structure
        // { "candidates": [ { "content": { "parts": [ { "text": "..." } ] } } ] }
        let content = response["candidates"][0]["content"]["parts"][0]["text"].as_str()
            .ok_or("No content in response (Gemini)")?;

        if content.contains("NULL") {
            return Ok("NULL".to_string());
        }

        let cleaned_content = content.trim().trim_start_matches("```json").trim_start_matches("```").trim_end_matches("```").trim();

        if serde_json::from_str::<Value>(cleaned_content).is_ok() {
            return Ok(cleaned_content.to_string());
        }

        Ok("NULL".to_string())
    }

    fn name(&self) -> String {
        "Gemini".to_string()
    }
}

pub fn get_provider(settings: &Settings) -> Box<dyn LLMProvider> {
    let model = &settings.server.model;
    let api_url = &settings.server.api_url;

    match settings.server.provider.to_lowercase().as_str() {
        "openai" => {
            let api_key = settings.server.api_key.clone().expect("API key is required for OpenAI provider");
            Box::new(OpenAiProvider::new(api_key, model, api_url.clone()))
        },
        "gemini" => {
            let api_key = settings.server.api_key.clone().expect("API key is required for Gemini provider");
            Box::new(GeminiProvider::new(api_key, model, api_url.clone()))
        },
        "ollama" | _ => {
            // Default to Ollama
            let api_url_str = api_url.as_deref().unwrap_or("http://localhost:11434/api/generate");
             Box::new(OllamaProvider::new(model, api_url_str))
        }
    }
}
