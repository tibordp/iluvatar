//! # iluvatar
//!
//! Random access into compressed streams: read individual files from
//! compressed tar and cpio archives, or any byte range of a bare compressed
//! file, without decompressing the whole thing.
//!
//! The library makes an indexing pass over the stream, periodically
//! snapshotting the decompressor state (and, for an archive, recording each
//! file's position). Subsequent reads restore the nearest snapshot and
//! decompress forward from there.
//!
//! ## Quick start
//!
//! The [`sync::Archive`] type wraps any `Read + Seek` reader:
//!
//! ```no_run
//! use iluvatar::sync::Archive;
//! use std::fs::File;
//!
//! let file = File::open("data.tar.gz").unwrap();
//! let mut archive = Archive::new(file).unwrap();
//!
//! // List entries
//! for entry in archive.list() {
//!     println!("{} ({} bytes)", entry.path, entry.size);
//! }
//!
//! // Read a file
//! let data = archive.read_file("path/to/file.txt").unwrap();
//!
//! // Read a byte range without decompressing the whole file
//! let header = archive.read_file_range("big.bin", 0, 1024).unwrap();
//! ```
//!
//! ## Checkpoint strategies
//!
//! The default checkpoint interval is tuned per compression format. You can
//! override it with a custom [`CheckpointStrategy`]:
//!
//! ```no_run
//! use iluvatar::sync::Archive;
//! use iluvatar::{FixedInterval, Budget, BudgetRatio};
//! use std::fs::File;
//!
//! // Fixed interval: checkpoint every 8 MiB
//! let archive = Archive::with_strategy(
//!     File::open("data.tar.gz")?,
//!     FixedInterval::new(8 * 1024 * 1024),
//! )?;
//!
//! // Budget: keep total checkpoint data under ~10 MiB
//! let archive = Archive::with_strategy(
//!     File::open("data.tar.zst")?,
//!     Budget::new(10 * 1024 * 1024),
//! )?;
//! # Ok::<(), iluvatar::Error>(())
//! ```
//!
//! ## Sans-I/O engine
//!
//! For async runtimes, WASM, or custom I/O, drive the engine directly.
//! It never calls `read()` or `seek()` — you feed it data and it tells
//! you what it needs next via [`EngineRequest`].
//!
//! ```
//! # fn example() -> iluvatar::Result<()> {
//! use iluvatar::{IndexingEngine, EngineRequest, CompressionFormat};
//!
//! # let compressed_data: &[u8] = &[];
//! let mut engine = IndexingEngine::new(
//!     CompressionFormat::Gzip,
//!     None, // auto-detect archive format
//!     0,    // archive size (0 = unknown)
//! )?;
//!
//! let mut offset = 0;
//! loop {
//!     match engine.step() {
//!         EngineRequest::NeedInput => {
//!             if offset >= compressed_data.len() {
//!                 engine.signal_eof();
//!             } else {
//!                 let end = (offset + 8192).min(compressed_data.len());
//!                 engine.provide_data(&compressed_data[offset..end]);
//!                 offset = end;
//!             }
//!         }
//!         EngineRequest::Done => break,
//!         EngineRequest::Error(e) => return Err(e),
//!         _ => {}
//!     }
//! }
//!
//! let index = engine.finish();
//! # Ok(())
//! # }
//! ```
//!
//! ## Modules
//!
//! - [`sync`] — Synchronous `Archive` and `Stream` APIs (most users want these)
//! - [`tokio`] — Async equivalents using tokio
//! - [`stream`] — Sans-I/O [`StreamIndexer`] and [`StreamReader`] over one
//!   compressed stream, container-agnostic
//! - [`engine`] — Sans-I/O [`IndexingEngine`] and [`ReadEngine`] for tar/cpio
//! - [`compress`] — Codecs, filters, chains and format detection
//! - [`archive`] — Archive format types and parsers (tar, cpio)
//! - [`index`] — Index types and serialization

pub mod archive;
pub mod compress;
pub(crate) mod cpio;
pub mod engine;
pub mod error;
pub mod index;
pub mod stream;
pub mod sync;
pub(crate) mod tar;

#[cfg(feature = "tokio")]
pub mod tokio;

// Re-exports for convenience
pub use archive::{ArchiveFormat, EntryType};
pub use compress::checkpoint::{Checkpoint, CheckpointState};
pub use compress::codec::{Bcj2Streams, BcjArch, Codec, CodecSpec};
pub use compress::decompressor::{DecompressResult, DecompressStatus, Decompressor};
pub use compress::CompressionFormat;
pub use engine::checkpoint_strategy::{
    default_interval_for_format, Budget, BudgetRatio, CheckpointContext, CheckpointStrategy,
    FixedInterval,
};
pub use engine::progress::IndexProgress;
pub use engine::request::EngineRequest;
pub use engine::state_machine::{IndexingEngine, ReadEngine};
pub use error::{Error, Result};
pub use index::entry::IndexEntry;
pub use index::store::ArchiveIndex;
pub use stream::{StreamIndex, StreamIndexer, StreamProgress, StreamReader};
