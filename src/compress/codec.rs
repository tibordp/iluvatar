//! What a stream is encoded with: one codec, or a chain of them.

use serde::{Deserialize, Serialize};

use crate::compress::decompressor::Decompressor;
use crate::compress::CompressionFormat;
use crate::error::{Error, Result};

pub use crate::compress::bcj2::Bcj2Streams;
pub use crate::compress::filter::BcjArch;

/// One decoding stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Codec {
    /// Stored bytes.
    Copy,
    /// Deflate; `raw` means no gzip framing (zip and 7z members).
    Deflate {
        raw: bool,
    },
    Bzip2,
    /// Raw LZMA1 with the `.lzma`-style properties byte, a dictionary size,
    /// and the unpacked length when the stream has no end marker.
    Lzma {
        props: u8,
        dict_size: u32,
        unpacked_len: Option<u64>,
    },
    /// Raw LZMA2 with its dictionary-size property byte.
    Lzma2 {
        dict_prop: u8,
    },
    /// The `.xz` container.
    Xz,
    Zstd,
    /// Byte delta with `distance` 1..=256.
    Delta {
        distance: u8,
    },
    Bcj(BcjArch),
    /// 7-Zip's four-stream x86 converter. Only the main stream flows
    /// through the chain; the caller decodes the CALL, JUMP and
    /// range-coder streams whole and supplies them with
    /// [`CodecSpec::set_bcj2_streams`]. They are never serialized: a spec
    /// loaded from disk carries `None`.
    Bcj2 {
        #[serde(skip)]
        streams: Option<std::sync::Arc<Bcj2Streams>>,
    },
    /// AES-256-CBC. The key is never serialized: an index loaded from disk
    /// carries `None` and the caller supplies it again with
    /// [`CodecSpec::set_aes_key`]. `len` is the plaintext length, which cuts
    /// the final block's padding.
    AesCbc {
        #[serde(skip)]
        key: Option<[u8; 32]>,
        iv: [u8; 16],
        len: Option<u64>,
    },
}

/// A stream's codecs in packed-to-unpacked order, so a 7z folder encoded
/// as `AES → LZMA2 → BCJ` is `[AesCbc, Lzma2, Bcj]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodecSpec(pub Vec<Codec>);

impl CodecSpec {
    pub fn single(codec: Codec) -> Self {
        Self(vec![codec])
    }

    /// Fill in the AES key after loading a serialized spec.
    pub fn set_aes_key(&mut self, key: [u8; 32]) {
        for codec in &mut self.0 {
            if let Codec::AesCbc { key: k, .. } = codec {
                *k = Some(key);
            }
        }
    }

    /// Hand the BCJ2 stage its side streams.
    pub fn set_bcj2_streams(&mut self, streams: std::sync::Arc<Bcj2Streams>) {
        for codec in &mut self.0 {
            if let Codec::Bcj2 { streams: s } = codec {
                *s = Some(streams.clone());
            }
        }
    }

    /// Build the decompressor for this spec.
    pub fn create(&self) -> Result<Box<dyn Decompressor>> {
        if self.0.is_empty() {
            return Err(Error::UnsupportedFormat);
        }
        let mut stages = Vec::with_capacity(self.0.len());
        for codec in &self.0 {
            stages.push(create_stage(codec)?);
        }
        if stages.len() == 1 {
            Ok(stages.pop().unwrap())
        } else {
            Ok(Box::new(crate::compress::chain::ChainDecompressor::new(
                stages,
            )?))
        }
    }
}

impl From<CompressionFormat> for CodecSpec {
    fn from(format: CompressionFormat) -> Self {
        CodecSpec::single(match format {
            CompressionFormat::None => Codec::Copy,
            CompressionFormat::Gzip => Codec::Deflate { raw: false },
            CompressionFormat::Bzip2 => Codec::Bzip2,
            CompressionFormat::Xz => Codec::Xz,
            CompressionFormat::Zstd => Codec::Zstd,
        })
    }
}

fn create_stage(codec: &Codec) -> Result<Box<dyn Decompressor>> {
    Ok(match codec {
        Codec::Copy => Box::new(crate::compress::none::NoneDecompressor::new()),

        #[cfg(feature = "gzip")]
        Codec::Deflate { raw: false } => Box::new(crate::compress::gzip::GzipDecompressor::new()),
        #[cfg(feature = "gzip")]
        Codec::Deflate { raw: true } => {
            Box::new(crate::compress::gzip::GzipDecompressor::new_raw())
        }

        #[cfg(feature = "bz2")]
        Codec::Bzip2 => Box::new(crate::compress::bzip2::Bzip2Decompressor::new()),

        #[cfg(feature = "xz")]
        Codec::Lzma {
            props,
            dict_size,
            unpacked_len,
        } => Box::new(crate::compress::lzma::LzmaDecompressor::from_props_byte(
            *props,
            *dict_size,
            *unpacked_len,
        )?),
        #[cfg(feature = "xz")]
        Codec::Lzma2 { dict_prop } => Box::new(
            crate::compress::lzma::Lzma2Decompressor::from_prop_byte(*dict_prop)?,
        ),
        #[cfg(feature = "xz")]
        Codec::Xz => Box::new(crate::compress::xz::XzDecompressor::new()),

        #[cfg(feature = "zstandard")]
        Codec::Zstd => Box::new(crate::compress::zstd_dec::ZstdDecompressor::new()),

        Codec::Delta { distance } => Box::new(crate::compress::filter::FilterDecompressor::delta(
            *distance as usize + 1,
        )?),
        Codec::Bcj(arch) => Box::new(crate::compress::filter::FilterDecompressor::bcj(*arch)),
        Codec::Bcj2 { streams } => {
            let streams = streams
                .clone()
                .ok_or_else(|| Error::InvalidState("BCJ2 stage without its side streams".into()))?;
            Box::new(crate::compress::bcj2::Bcj2Decompressor::new(streams)?)
        }

        #[cfg(feature = "aes")]
        Codec::AesCbc { key, iv, len } => {
            let key = key.ok_or_else(|| {
                Error::InvalidState("AES codec has no key; call CodecSpec::set_aes_key".into())
            })?;
            Box::new(crate::compress::aes::AesCbcDecryptor::new(&key, *iv, *len))
        }

        #[allow(unreachable_patterns)]
        _ => return Err(Error::UnsupportedFormat),
    })
}
