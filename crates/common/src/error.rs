use thiserror::Error;

/// Errors shared across the Oxide crates for config and key handling.
#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid key: {0}")]
    Key(String),

    #[error("invalid config: {0}")]
    Config(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("toml parse error: {0}")]
    Toml(#[from] toml::de::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
