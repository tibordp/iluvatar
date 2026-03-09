//! Synchronous API for reading compressed archives.
//!
//! [`Archive`] wraps any reader that implements [`std::io::Read`] (for
//! indexing) or [`std::io::Read`] + [`std::io::Seek`] (for reading files).
//!
//! # Examples
//!
//! Read a file from a gzip-compressed tar archive:
//!
//! ```no_run
//! use iluvatar::sync::Archive;
//! use std::fs::File;
//!
//! let file = File::open("archive.tar.gz")?;
//! let mut archive = Archive::new(file)?;
//! let data = archive.read_file("path/in/archive.txt")?;
//! # Ok::<(), iluvatar::Error>(())
//! ```
//!
//! Stream a large file without buffering it all in memory:
//!
//! ```no_run
//! use iluvatar::sync::Archive;
//! use std::fs::File;
//! use std::io::Read;
//!
//! let file = File::open("archive.tar.zst")?;
//! let mut archive = Archive::new(file)?;
//! let mut reader = archive.open("large-file.bin")?;
//!
//! let mut buf = [0u8; 8192];
//! loop {
//!     let n = reader.read(&mut buf)?;
//!     if n == 0 { break; }
//!     // process buf[..n]
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Build an index from a non-seekable reader (e.g. a pipe), then
//! use it later with a seekable file:
//!
//! ```no_run
//! use iluvatar::sync::Archive;
//! use std::fs::File;
//!
//! // Index from stdin (forward-only)
//! let index = {
//!     let stdin = std::io::stdin().lock();
//!     let archive = Archive::from_reader(stdin, 0)?;
//!     let (_, index) = archive.into_parts();
//!     index
//! };
//!
//! // Re-open with seeking for random access
//! let file = File::open("archive.tar.gz")?;
//! let mut archive = Archive::from_parts(file, index);
//! let data = archive.read_file("some/file.txt")?;
//! # Ok::<(), iluvatar::Error>(())
//! ```

mod reader;

pub use reader::{Archive, EntryReader};
