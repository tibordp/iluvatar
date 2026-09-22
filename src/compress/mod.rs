//! Decoding stages and compression format detection.
//!
//! Every codec implements [`Decompressor`](decompressor::Decompressor): a
//! sans-I/O interface that consumes compressed bytes, produces decompressed
//! output, and can checkpoint and restore its internal state. Stages compose
//! into a [`ChainDecompressor`](chain::ChainDecompressor); a
//! [`CodecSpec`](codec::CodecSpec) names a stream's stages and builds the
//! decompressor for it.
//!
//! The xz, LZMA and zstd decoders are built in rather than wrapping C
//! libraries, because checkpoint/resume requires serializing the full
//! decoder state, which C library wrappers don't expose.

pub mod bcj2;
pub mod chain;
pub mod checkpoint;
pub mod codec;
pub mod decompressor;
pub(crate) mod detect;
pub mod filter;

#[cfg(feature = "aes")]
pub mod aes;

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
