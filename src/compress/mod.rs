pub mod checkpoint;
pub mod decompressor;
pub mod detect;

#[cfg(feature = "gzip")]
pub mod gzip;

#[cfg(feature = "bz2")]
pub mod bzip2;

#[cfg(feature = "xz")]
pub mod lzma;

#[cfg(feature = "xz")]
pub mod xz;

#[cfg(feature = "zstandard")]
pub mod zstd_dec;

pub mod none;

use serde::{Deserialize, Serialize};

/// Detected or specified compression format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CompressionFormat {
    None,
    Gzip,
    Bzip2,
    Xz,
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
