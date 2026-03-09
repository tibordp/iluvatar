//! Archive format types and parsers.
//!
//! This module defines the format-agnostic interface shared by tar and cpio:
//!
//! - [`EntryType`] — File type enum (regular, directory, symlink, etc.).
//! - [`ArchiveFormat`] — Enum distinguishing tar from cpio.

pub(crate) mod detect;
pub mod entry;
pub(crate) mod parser;

use serde::{Deserialize, Serialize};

pub(crate) use entry::ArchiveEntry;
pub use entry::EntryType;
pub(crate) use parser::{ArchiveEvent, ArchiveParser};

/// The archive container format (orthogonal to compression).
///
/// iluvatar supports both tar and cpio archives, optionally wrapped in
/// any supported compression format. The archive format is typically
/// auto-detected from the first decompressed bytes.
///
/// # Example
///
/// ```
/// use iluvatar::ArchiveFormat;
///
/// let fmt = ArchiveFormat::Tar;
/// assert_eq!(fmt.to_string(), "tar");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArchiveFormat {
    /// tar archive (ustar, GNU, PAX, or V7).
    Tar,
    /// cpio archive (newc/SVR4 or odc/POSIX.1).
    Cpio,
}

impl std::fmt::Display for ArchiveFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArchiveFormat::Tar => write!(f, "tar"),
            ArchiveFormat::Cpio => write!(f, "cpio"),
        }
    }
}
