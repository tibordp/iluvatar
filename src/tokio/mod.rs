//! Async API for reading compressed archives using tokio.
//!
//! This is the async counterpart to [`crate::sync`]. [`Archive`] wraps
//! any reader that implements [`tokio::io::AsyncRead`] (for indexing) or
//! [`tokio::io::AsyncRead`] + [`tokio::io::AsyncSeek`] (for reading files).
//!
//! # Examples
//!
//! ```no_run
//! # async fn example() -> Result<(), iluvatar::Error> {
//! use iluvatar::tokio::Archive;
//!
//! let file = tokio::fs::File::open("archive.tar.gz").await?;
//! let mut archive = Archive::new(file).await?;
//!
//! for entry in archive.list() {
//!     println!("{}", entry.path);
//! }
//!
//! let data = archive.read_file("path/in/archive.txt").await?;
//! # Ok(())
//! # }
//! ```
//!
//! Stream a file using [`tokio::io::copy`]:
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use iluvatar::tokio::Archive;
//!
//! let file = tokio::fs::File::open("archive.tar.zst").await?;
//! let mut archive = Archive::new(file).await?;
//!
//! let mut reader = archive.open("large-file.bin").await?;
//! let mut stdout = tokio::io::stdout();
//! tokio::io::copy(&mut reader, &mut stdout).await?;
//! # Ok(())
//! # }
//! ```

mod reader;

pub use reader::{Archive, EntryReader};
