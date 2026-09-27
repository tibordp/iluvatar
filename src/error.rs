/// Errors that can occur during iluvatar operations.
///
/// All variants can be displayed as human-readable messages via the
/// [`Display`](std::fmt::Display) implementation.
///
/// # Example
///
/// ```
/// use iluvatar::Error;
///
/// let err = Error::FileNotFound("missing.txt".into());
/// assert_eq!(err.to_string(), "file not found in archive: missing.txt");
/// ```
///
/// Marked `#[non_exhaustive]`: supporting a new format usually brings a new
/// error variant, so matches on it need a wildcard arm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The compression format is not recognized or not enabled via feature flags.
    #[error("unsupported compression format")]
    UnsupportedFormat,

    /// A tar header could not be parsed.
    #[error("invalid tar header: {0}")]
    InvalidTarHeader(String),

    /// A cpio header could not be parsed.
    #[error("invalid cpio header: {0}")]
    InvalidCpioHeader(String),

    /// An ar header could not be parsed.
    #[error("invalid ar header: {0}")]
    InvalidArHeader(String),

    /// The decompressor encountered invalid or corrupt data.
    #[error("decompression error: {0}")]
    DecompressionError(String),

    /// A decompressor checkpoint could not be created or restored.
    #[error("checkpoint error: {0}")]
    CheckpointError(String),

    /// The requested file path was not found in the archive index.
    #[error("file not found in archive: {0}")]
    FileNotFound(String),

    /// An error occurred while building or loading an index.
    #[error("index error: {0}")]
    IndexError(String),

    /// The stored index was built by an incompatible version.
    #[error("index version mismatch: expected {expected}, got {got}")]
    IndexVersionMismatch {
        /// Version this library expects.
        expected: u32,
        /// Version found in the serialized index.
        got: u32,
    },

    /// The archive has been modified since the index was built. Not
    /// currently returned by iluvatar; reserved for callers' own checks.
    #[error("archive changed since index was built")]
    StaleIndex,

    /// The compressed stream ended early: cut off before its end marker,
    /// or shorter than the index says. Indexing an archive reports this
    /// as [`TruncatedArchive`](Self::TruncatedArchive) instead.
    #[error("truncated input")]
    TruncatedInput,

    /// The archive ended somewhere a well-formed archive cannot end, such
    /// as inside a header or a member's data, or its compressed stream was
    /// cut off.
    #[error("truncated archive: {0}")]
    TruncatedArchive(String),

    /// An I/O error occurred (the [`std::io::Error`]'s message).
    #[error("I/O error: {0}")]
    Io(String),

    /// A serialization or deserialization error occurred.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// An internal state invariant was violated.
    #[error("invalid state: {0}")]
    InvalidState(String),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

/// Result type alias for iluvatar operations.
pub type Result<T> = std::result::Result<T, Error>;
