//! # supertar
//!
//! Efficient random access to files within compressed tar/cpio archives.
//!
//! supertar builds an index of a compressed archive, including periodic
//! decompressor state checkpoints, enabling fast random access to any file
//! without decompressing the entire archive from the beginning.
//!
//! ## Key Features
//!
//! - **Sans-I/O core**: The engine never performs I/O itself, making it
//!   compatible with both sync and async runtimes.
//! - **Multiple compression formats**: gzip, bzip2, xz, zstd, and uncompressed.
//! - **Persistent index**: Index can be serialized to disk and reused.
//! - **Decompression checkpoints**: Periodic snapshots of decompressor state
//!   allow seeking to nearby positions without full re-decompression.
//!
//! ## Quick Start (Sync)
//!
//! ```no_run
//! use supertar::sync::Archive;
//! use std::fs::File;
//!
//! let file = File::open("data.tar.gz").unwrap();
//! let mut archive = Archive::new(file).unwrap();
//! for entry in archive.list() {
//!     println!("{} ({} bytes)", entry.path, entry.size);
//! }
//! let contents = archive.read_file("path/to/file.txt").unwrap();
//! ```
//!
//! ## Sans-I/O Usage
//!
//! For async or custom I/O, use the engine directly:
//!
//! ```no_run
//! use supertar::engine::state_machine::IndexingEngine;
//! use supertar::engine::request::EngineRequest;
//! use supertar::compress::CompressionFormat;
//!
//! let mut engine = IndexingEngine::new(
//!     CompressionFormat::Gzip,
//!     None,        // auto-detect archive format (tar vs cpio)
//!     1024 * 1024, // checkpoint every 1 MiB
//!     0,           // archive size (can be 0 if unknown)
//! ).unwrap();
//!
//! // Drive the engine with your own I/O:
//! // loop {
//! //     match engine.step() {
//! //         EngineRequest::NeedInput => { /* read data, call engine.provide_data() */ }
//! //         EngineRequest::Done => break,
//! //         _ => {}
//! //     }
//! // }
//! // let index = engine.finish();
//! ```

pub mod archive;
pub mod compress;
pub mod cpio;
pub mod engine;
pub mod error;
pub mod index;
pub mod sync;
pub mod tar;

#[cfg(feature = "tokio")]
pub mod tokio;

// Re-exports for convenience
pub use archive::{ArchiveFormat, EntryType};
pub use compress::CompressionFormat;
pub use engine::progress::IndexProgress;
pub use engine::request::EngineRequest;
pub use engine::state_machine::{IndexingEngine, ReadEngine, DEFAULT_CHECKPOINT_INTERVAL};
pub use error::{Result, SupertarError};
pub use index::entry::IndexEntry;
pub use index::store::ArchiveIndex;
