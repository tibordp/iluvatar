/// Errors that can occur during supertar operations.
#[derive(Debug, thiserror::Error)]
pub enum SupertarError {
    #[error("unsupported compression format")]
    UnsupportedFormat,

    #[error("invalid tar header: {0}")]
    InvalidTarHeader(String),

    #[error("invalid cpio header: {0}")]
    InvalidCpioHeader(String),

    #[error("decompression error: {0}")]
    DecompressionError(String),

    #[error("checkpoint error: {0}")]
    CheckpointError(String),

    #[error("file not found in archive: {0}")]
    FileNotFound(String),

    #[error("index error: {0}")]
    IndexError(String),

    #[error("index version mismatch: expected {expected}, got {got}")]
    IndexVersionMismatch { expected: u32, got: u32 },

    #[error("archive changed since index was built")]
    StaleIndex,

    #[error("truncated input")]
    TruncatedInput,

    #[error("I/O error: {0}")]
    Io(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("invalid state: {0}")]
    InvalidState(String),
}

impl From<std::io::Error> for SupertarError {
    fn from(e: std::io::Error) -> Self {
        SupertarError::Io(e.to_string())
    }
}

/// Result type alias for supertar operations.
pub type Result<T> = std::result::Result<T, SupertarError>;
