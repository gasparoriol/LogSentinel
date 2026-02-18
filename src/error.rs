use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("LLM provider error: {0}")]
    Provider(String),

    #[error("Missing API key for provider '{0}'")]
    MissingApiKey(String),

    #[error("Invalid rate-limit configuration: {0}")]
    RateLimit(String),

    #[error("Dispatch error: {0}")]
    Dispatch(String),
}

pub type Result<T> = std::result::Result<T, AppError>;
