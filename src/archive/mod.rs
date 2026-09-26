//! Archive format types and parsers.
//!
//! This module defines the format-agnostic interface shared by tar, cpio and ar:
//!
//! - [`EntryType`] — File type enum (regular, directory, symlink, etc.).
//! - [`ArchiveFormat`] — Enum distinguishing tar, cpio and ar.

pub(crate) mod detect;
pub mod entry;
pub(crate) mod parser;

use serde::{Deserialize, Serialize};

pub(crate) use entry::ArchiveEntry;
pub use entry::EntryType;
pub(crate) use parser::{ArchiveEvent, ArchiveParser};

/// The archive container format (orthogonal to compression).
///
/// iluvatar supports tar, cpio and ar archives, optionally wrapped in
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
///
/// Marked `#[non_exhaustive]`: new container formats may be added in minor
/// releases, so matches on it need a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ArchiveFormat {
    /// tar archive (ustar, GNU, PAX, or V7).
    Tar,
    /// cpio archive (newc/SVR4 or odc/POSIX.1).
    Cpio,
    /// ar archive (GNU/SysV, BSD, and Windows `.lib`), as used for static
    /// libraries and Debian packages.
    Ar,
}

impl std::fmt::Display for ArchiveFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArchiveFormat::Tar => write!(f, "tar"),
            ArchiveFormat::Cpio => write!(f, "cpio"),
            ArchiveFormat::Ar => write!(f, "ar"),
        }
    }
}
