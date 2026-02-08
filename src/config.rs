use serde::Deserialize;
use crate::models::LogSource;


#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub model: String,
    pub api_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BffConfig {
    pub url: String,
    pub token: String,
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct EmailConfig {
    pub recipient: String,
    pub from: String,
    pub api_url: String,
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct FileConfig {
    pub path: String,
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub server: ServerConfig,
    pub bff: BffConfig,
    pub email: EmailConfig,
    pub logger: FileConfig,
    pub log_path: String,
    pub source: LogSource,
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