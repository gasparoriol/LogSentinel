use async_trait::async_trait;
use reqwest::Client;
use serde_json::{json, Value};
use secrecy::{SecretString, ExposeSecret};
use crate::models::LogSource;
use crate::config::Settings;
use crate::error::AppError;

#[async_trait]
pub trait LLMProvider: Send + Sync {
    async fn analyze(&self, log_line: &str, source: &LogSource) -> Result<String, Box<dyn std::error::Error>>;
    
    async fn analyze_batch(&self, log_lines: &[String], source: &LogSource) -> Result<String, Box<dyn std::error::Error>>;

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
            "Act as a Senior Security Operations Center (SOC) Analyst. Analyze the following log entry from a {} environment: \"{}\".
            Instructions:
            Evaluate indicators of compromise (IoC) such as SQL Injection patterns, Path Traversal (../), unusual User-Agents, or Spring Security exceptions (e.g., InsufficientAuthenticationException repeated).
            Differentiate between a common application error (e.g., 404 on a missing favicon) and a targeted probe.
            If the log represents a legitimate security threat or a suspicious reconnaissance activity, return ONLY a JSON object with:
            'severity': (LOW, MEDIUM, HIGH, CRITICAL)
            'attack_type': (e.g., SQLi, XSS, Brute Force, Path Traversal, SSRF)
            'description': A brief explanation of why this is a threat.
            If the log is a routine system error, a standard 200/302 response, or noise without security implications, respond ONLY with the string: 'NULL'.",
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

    async fn analyze_batch(&self, log_lines: &[String], source: &LogSource) -> Result<String, Box<dyn std::error::Error>> {
        let mut logs_formatted = String::new();
        for (i, line) in log_lines.iter().enumerate() {
            logs_formatted.push_str(&format!("{}. \"{}\"\n", i, line));
        }

        let prompt = format!(
            "Act as a Senior SOC Analyst. Analyze these {} logs from {}:\n{}\n
            Instructions:
            1. Evaluate each log for security threats (SQLi, XSS, Path Traversal, etc.).
            2. For each log, you MUST respond with a JSON object.
            3. If the log is a THREAT, include: 'index', 'severity' (LOW, MEDIUM, HIGH, CRITICAL), 'attack_type', and 'description'.
            4. If the log is BENIGN, include: 'index' and 'status': 'NULL'.
            5. Return the results as a JSON array of these objects under a 'results' key.
            Example: {{ \"results\": [ {{ \"index\": 0, \"status\": \"NULL\" }}, {{ \"index\": 1, \"severity\": \"HIGH\", ... }} ] }}
            Return ONLY valid JSON.",
            log_lines.len(),
            source.get_context(),
            logs_formatted
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

        Ok(response["response"].as_str().unwrap_or("[]").to_string())
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

    async fn analyze_batch(&self, log_lines: &[String], source: &LogSource) -> Result<String, Box<dyn std::error::Error>> {
        let mut logs_formatted = String::new();
        for (i, line) in log_lines.iter().enumerate() {
            logs_formatted.push_str(&format!("{}. \"{}\"\n", i, line));
        }

        let prompt = format!(
            "Analyze these {} logs from {}:\n{}\n
            Respond ONLY with a JSON array of objects.
            Each object: 'index', 'severity', 'attack_type', 'description'.
            If not a threat: {{'index': i, 'status': 'NULL'}}.",
            log_lines.len(),
            source.get_context(),
            logs_formatted
        );

        let response = self.client.post(&self.api_url)
              .header("Authorization", format!("Bearer {}", self.api_key.expose_secret()))
              .json(&json!({
                  "model": &self.model,
                  "messages": [
                      {"role": "system", "content": "You are a cybersecurity expert. Response in JSON format only (array of objects)."},
                      {"role": "user", "content": prompt}
                  ],
                  "temperature": 0
              }))
              .send()
              .await?
              .json::<Value>()
              .await?;

        let content = response["choices"][0]["message"]["content"].as_str().ok_or("No content")?;
        let cleaned = content.trim().trim_start_matches("```json").trim_start_matches("```").trim_end_matches("```").trim();
        Ok(cleaned.to_string())
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
    async fn analyze_batch(&self, log_lines: &[String], source: &LogSource) -> Result<String, Box<dyn std::error::Error>> {
        let mut logs_formatted = String::new();
        for (i, line) in log_lines.iter().enumerate() {
            logs_formatted.push_str(&format!("{}. \"{}\"\n", i, line));
        }

        let prompt = format!(
            "Analyze these {} logs from {}:\n{}\n
            Respond ONLY with a JSON array of objects.
            Each object: 'index', 'severity', 'attack_type', 'description'.
            If not a threat: {{'index': i, 'status': 'NULL'}}.",
            log_lines.len(),
            source.get_context(),
            logs_formatted
        );

        let url = format!("{}/{}:generateContent?key={}", self.api_url, self.model, self.api_key.expose_secret());
        let response = self.client.post(&url)
            .json(&json!({
                "contents": [{ "parts": [{ "text": prompt }] }]
            }))
            .send()
            .await?
            .json::<Value>()
            .await?;

        let content = response["candidates"][0]["content"]["parts"][0]["text"].as_str().ok_or("No content")?;
        let cleaned = content.trim().trim_start_matches("```json").trim_start_matches("```").trim_end_matches("```").trim();
        Ok(cleaned.to_string())
    }
    fn name(&self) -> String {
        "Gemini".to_string()
    }
}

pub struct ClaudeProvider {
    client: Client,
    api_key: SecretString,
    model: String,
}

impl ClaudeProvider {
    pub fn new(api_key: SecretString, model: &str) -> Self {
        Self {
            client: Client::new(),
            api_key,
            model: model.to_string(),
        }
    }
}

#[async_trait]
impl LLMProvider for ClaudeProvider {
    async fn analyze(&self, log_line: &str, source: &LogSource) -> Result<String, Box<dyn std::error::Error>> {
        let prompt = format!(
            "Analyze this log of {}: \"{}\". If it is a threat, respond ONLY with a JSON object containing: \
            'severity' (LOW, MEDIUM, HIGH, CRITICAL), 'attack_type', and 'description'. \
            If it is NOT a threat, respond with the word 'NULL'.",
            source.get_context(),
            log_line
        );

        let response = self.client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", self.api_key.expose_secret())
            .header("anthropic-version", "2023-06-01")
            .json(&json!({
                "model": &self.model,
                "max_tokens": 1024,
                "messages": [{"role": "user", "content": prompt}]
            }))
            .send()
            .await?
            .json::<Value>()
            .await?;

        let content = response["content"][0]["text"].as_str()
            .ok_or("No content in Claude response")?;

        if content.contains("NULL") {
            return Ok("NULL".to_string());
        }

        let cleaned = content
            .trim()
            .trim_start_matches("```json")
            .trim_start_matches("```")
            .trim_end_matches("```")
            .trim();

        if serde_json::from_str::<Value>(cleaned).is_ok() {
            return Ok(cleaned.to_string());
        }

        Ok("NULL".to_string())
    }

    fn name(&self) -> String {
        "Claude".to_string()
    }

    async fn analyze_batch(&self, log_lines: &[String], source: &LogSource) -> Result<String, Box<dyn std::error::Error>> {
        let mut logs_formatted = String::new();
        for (i, line) in log_lines.iter().enumerate() {
            logs_formatted.push_str(&format!("{}. \"{}\"\n", i, line));
        }

        let prompt = format!(
            "Analyze these {} logs from {}:\n{}\n
            Respond ONLY with a JSON array of objects.
            Each object: 'index', 'severity', 'attack_type', 'description'.
            If not a threat: {{'index': i, 'status': 'NULL'}}.",
            log_lines.len(),
            source.get_context(),
            logs_formatted
        );

        let response = self.client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", self.api_key.expose_secret())
            .header("anthropic-version", "2023-06-01")
            .json(&json!({
                "model": &self.model,
                "max_tokens": 1024,
                "messages": [{"role": "user", "content": prompt}]
            }))
            .send()
            .await?
            .json::<Value>()
            .await?;

        let content = response["content"][0]["text"].as_str().ok_or("No content")?;
        let cleaned = content.trim().trim_start_matches("```json").trim_start_matches("```").trim_end_matches("```").trim();
        Ok(cleaned.to_string())
    }
}

pub fn get_provider(settings: &Settings) -> crate::error::Result<Box<dyn LLMProvider>> {
    let model = &settings.server.model;
    let api_url = &settings.server.api_url;

    let provider: Box<dyn LLMProvider> = match settings.server.provider.to_lowercase().as_str() {
        "openai" => {
            let api_key = settings.server.api_key.clone()
                .ok_or_else(|| AppError::MissingApiKey("openai".into()))?;
            Box::new(OpenAiProvider::new(api_key, model, api_url.clone()))
        },
        "gemini" => {
            let api_key = settings.server.api_key.clone()
                .ok_or_else(|| AppError::MissingApiKey("gemini".into()))?;
            Box::new(GeminiProvider::new(api_key, model, api_url.clone()))
        },
        "claude" => {
            let api_key = settings.server.api_key.clone()
                .ok_or_else(|| AppError::MissingApiKey("claude".into()))?;
            Box::new(ClaudeProvider::new(api_key, model))
        },
        _ => {
            // Default to Ollama
            let api_url_str = api_url.as_deref().unwrap_or("http://localhost:11434/api/generate");
            Box::new(OllamaProvider::new(model, api_url_str))
        }
    };

    Ok(provider)
}
