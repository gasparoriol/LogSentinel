use serde::Deserialize;
use crate::models::LogSource;
use secrecy::SecretString;

#[derive(Clone, Debug, Deserialize)]
pub struct ServerConfig {
    pub provider: String,
    pub model: String,
    pub api_url: Option<String>,
    pub api_key: Option<SecretString>,
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

#[derive(Clone, Debug, Deserialize)]
pub struct LogFilterConfig {
    pub exact_patterns: Vec<String>,
    pub case_insensitive_patterns: Vec<String>,
    pub error_codes: Vec<String>,
    pub nmap_patterns: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RateLimitConfig {
    pub burst: u32,
    pub period_seconds: u64,
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
}

impl Settings {
    pub fn new(config_path: Option<&str>) -> Result<Self, config::ConfigError> {
        let mut builder = config::Config::builder();

        if let Some(path) = config_path {
            builder = builder.add_source(config::File::with_name(path));
        } else {
            builder = builder.add_source(config::File::with_name("Settings"));
        }

        let s = builder
            .add_source(config::Environment::with_prefix("APP"))
            .build()?;
        s.try_deserialize()
    }
}