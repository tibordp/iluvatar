//! # iluvatar
//!
//! Read individual files from compressed tar and cpio archives without
//! decompressing the whole thing.
//!
//! The library makes an indexing pass over the archive, recording each file's
//! position and periodically snapshotting the decompressor state. Subsequent
//! reads restore the nearest snapshot and decompress forward — typically
//! at most 1 MiB regardless of archive size.
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
//! ## Sans-I/O engine
//!
//! For async runtimes, WASM, or custom I/O, drive the engine directly.
//! It never calls `read()` or `seek()` — you feed it data and it tells
//! you what it needs next via [`EngineRequest`].
//!
//! ```no_run
//! use iluvatar::{IndexingEngine, EngineRequest, CompressionFormat};
//!
//! let mut engine = IndexingEngine::new(
//!     CompressionFormat::Gzip,
//!     None,        // auto-detect archive format
//!     1024 * 1024, // checkpoint interval
//!     0,           // archive size (0 = unknown)
//! ).unwrap();
//!
//! // loop {
//! //     match engine.step() {
//! //         EngineRequest::NeedInput => { /* provide data */ }
//! //         EngineRequest::Done => break,
//! //         _ => {}
//! //     }
//! // }
//! // let index = engine.finish();
//! ```
//!
//! ## Modules
//!
//! - [`sync`] — Synchronous `Archive` API (most users want this)
//! - [`tokio`] — Async equivalent using tokio
//! - [`engine`] — Sans-I/O [`IndexingEngine`] and [`ReadEngine`]
//! - [`compress`] — Decompressor implementations and format detection
//! - [`archive`] — Archive format types and parsers (tar, cpio)
//! - [`index`] — Index types and serialization

pub mod archive;
pub mod compress;
pub(crate) mod cpio;
pub mod engine;
pub mod error;
pub mod index;
pub mod sync;
pub(crate) mod tar;

#[cfg(feature = "tokio")]
pub mod tokio;

// Re-exports for convenience
pub use archive::{ArchiveFormat, EntryType};
pub use compress::CompressionFormat;
pub use engine::progress::IndexProgress;
pub use engine::request::EngineRequest;
pub use engine::state_machine::{IndexingEngine, ReadEngine, DEFAULT_CHECKPOINT_INTERVAL};
pub use error::{Result, Error};
pub use index::entry::IndexEntry;
pub use index::store::ArchiveIndex;
