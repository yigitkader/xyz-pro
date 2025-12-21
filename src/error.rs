use thiserror::Error;

#[derive(Error, Debug)]
pub enum ScannerError {
    #[error("GPU error: {0}")]
    Gpu(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),
}

pub type Result<T> = std::result::Result<T, ScannerError>;
