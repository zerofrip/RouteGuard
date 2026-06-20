use thiserror::Error;

pub type Result<T> = std::result::Result<T, RouteGuardError>;

#[derive(Debug, Error)]
pub enum RouteGuardError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("tunnel error: {0}")]
    Tunnel(String),

    #[error("routing error: {0}")]
    Routing(String),

    #[error("network lock error: {0}")]
    NetworkLock(String),

    #[error("IPC error: {0}")]
    Ipc(String),

    #[error("platform error: {0}")]
    Platform(String),

    #[error("DNS error: {0}")]
    Dns(String),

    #[error("service not running")]
    ServiceNotRunning,

    #[error("invalid state: {0}")]
    InvalidState(String),

    #[error("not supported on this platform")]
    UnsupportedPlatform,

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),

    #[error(transparent)]
    Toml(#[from] toml::de::Error),

    #[error(transparent)]
    TomlSerialize(#[from] toml::ser::Error),
}
