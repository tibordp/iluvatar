pub mod detect;
pub mod entry;
pub mod parser;

use serde::{Deserialize, Serialize};

pub use entry::{ArchiveEntry, EntryType};
pub use parser::{ArchiveEvent, ArchiveParser};

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
