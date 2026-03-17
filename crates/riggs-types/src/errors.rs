use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum RiggsError {
    #[error("platform error: {0}")]
    Platform(String),

    #[error("sensor error: {0}")]
    Sensor(String),

    #[error("engine error: {0}")]
    Engine(String),

    #[error("store error: {0}")]
    Store(String),

    #[error("comms error: {0}")]
    Comms(String),

    #[error("response error: {0}")]
    Response(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("intel error: {0}")]
    Intel(String),

    #[error("io error: {0}")]
    Io(String),

    #[error("json error: {0}")]
    Json(String),

    #[error("{0}")]
    Other(String),
}

impl From<std::io::Error> for RiggsError {
    fn from(err: std::io::Error) -> Self {
        RiggsError::Io(err.to_string())
    }
}

impl From<serde_json::Error> for RiggsError {
    fn from(err: serde_json::Error) -> Self {
        RiggsError::Json(err.to_string())
    }
}
