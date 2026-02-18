use serde::{Deserialize, Serialize};
use crate::models::LogSource;
use secrecy::SecretString;

#[derive(Clone, Debug, Deserialize)]
pub struct ServerConfig {
    pub provider: String,
    pub model: String,
    pub api_url: Option<String>,
    pub api_key: Option<SecretString>,
    pub api_key_file: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BffConfig {
    pub url: String,
    pub token: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct EmailConfig {
    pub recipient: String,
    pub from: String,
    pub api_url: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct FileConfig {
    pub path: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ThreatSignature {
    pub id: String,
    pub pattern: String,
    #[serde(rename = "type")]
    pub sig_type: SignatureType,
    pub description: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SignatureType {
    Exact,
    CaseInsensitive,
    Regex,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignaturesFile {
    pub signatures: Vec<ThreatSignature>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct LogFilterConfig {
    pub signatures_path: String,
    pub error_codes: Vec<String>,
    pub multiline_pattern: Option<String>,
    #[serde(skip)]
    pub signatures: Vec<ThreatSignature>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RateLimitConfig {
    pub burst: u32,
    pub period_seconds: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AnalysisConfig {
    pub batch_size: usize,
    pub batch_timeout_ms: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub port: u16,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Settings {
    pub server: ServerConfig,
    pub bff: BffConfig,
    pub email: EmailConfig,
    pub rats: RateLimitConfig, // Using 'rats' as convenient short name or 'ratelimit'
    pub logger: FileConfig,
    pub log_path: String,
    pub source: LogSource,
    pub filter: LogFilterConfig,
    pub analysis: AnalysisConfig,
    pub metrics: MetricsConfig,
}

impl Settings {
    pub fn new(config_path: Option<&str>, api_key_file_path: Option<String>) -> Result<Self, config::ConfigError> {
        let mut builder = config::Config::builder();

        if let Some(path) = config_path {
            builder = builder.add_source(config::File::with_name(path));
        } else {
            builder = builder.add_source(config::File::with_name("Settings"));
        }

        let s = builder
            .add_source(config::Environment::with_prefix("APP"))
            .build()?;
        
        let mut settings: Settings = s.try_deserialize()?;

        // CLI argument overrides config file
        if let Some(cli_path) = api_key_file_path {
            settings.server.api_key_file = Some(cli_path);
        }

        if settings.server.api_key.is_none() {
            if let Some(path) = &settings.server.api_key_file {
                let key = std::fs::read_to_string(path)
                    .map_err(|e| config::ConfigError::Message(format!("Failed to read api_key_file '{}': {}", path, e)))?;
                settings.server.api_key = Some(SecretString::new(key.trim().to_string()));
            }
        }

        // Load threat signatures
        let sig_path = &settings.filter.signatures_path;
        let sig_content = std::fs::read_to_string(sig_path)
            .map_err(|e| config::ConfigError::Message(format!("Failed to read signatures file '{}': {}", sig_path, e)))?;
        let sig_file: SignaturesFile = toml::from_str(&sig_content)
            .map_err(|e| config::ConfigError::Message(format!("Failed to parse signatures file '{}': {}", sig_path, e)))?;
        
        settings.filter.signatures = sig_file.signatures;

        Ok(settings)
    }
}