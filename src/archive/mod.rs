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

pub use entry::EntryType;
pub(crate) use entry::ArchiveEntry;
pub(crate) use parser::{ArchiveEvent, ArchiveParser};

/// The archive container format (orthogonal to compression).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArchiveFormat {
    Tar,
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
