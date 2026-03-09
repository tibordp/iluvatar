//! Decompressor implementations and compression format detection.
//!
//! Each supported compression format has its own submodule implementing
//! a `Decompressor` trait — a sans-I/O interface that consumes compressed
//! bytes and produces decompressed output, with support for checkpointing
//! and restoring internal state.
//!
//! The xz and zstd decompressors are built-in rather than wrapping C
//! libraries, because checkpoint/resume requires serializing the full
//! decompressor state, which C library wrappers don't expose.

pub mod checkpoint;
pub(crate) mod decompressor;
pub(crate) mod detect;

#[cfg(feature = "gzip")]
pub(crate) mod gzip;

#[cfg(feature = "bz2")]
pub(crate) mod bzip2;

#[cfg(feature = "xz")]
pub(crate) mod lzma;

#[cfg(feature = "xz")]
pub(crate) mod xz;

#[cfg(feature = "zstandard")]
pub(crate) mod zstd_dec;

pub(crate) mod none;

use serde::{Deserialize, Serialize};

/// Detected or specified compression format.
///
/// Used both as a detection result and as
/// metadata stored in the index.
///
/// # Example
///
/// ```
/// use iluvatar::CompressionFormat;
///
/// let fmt = CompressionFormat::Gzip;
/// assert_eq!(fmt.to_string(), "gzip");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CompressionFormat {
    /// No compression (raw tar/cpio).
    None,
    /// Gzip (DEFLATE) compression.
    Gzip,
    /// Bzip2 compression.
    Bzip2,
    /// XZ (LZMA2) compression.
    Xz,
    /// Zstandard compression.
    Zstd,
}

impl std::fmt::Display for CompressionFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompressionFormat::None => write!(f, "none"),
            CompressionFormat::Gzip => write!(f, "gzip"),
            CompressionFormat::Bzip2 => write!(f, "bzip2"),
            CompressionFormat::Xz => write!(f, "xz"),
            CompressionFormat::Zstd => write!(f, "zstd"),
        }
    }
}
