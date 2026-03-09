//! Index types and serialization.
//!
//! An [`ArchiveIndex`](store::ArchiveIndex) maps file paths to their
//! positions in the uncompressed stream, along with decompressor
//! checkpoints that enable seeking. It can be serialized to bytes
//! with [`to_bytes()`](store::ArchiveIndex::to_bytes) and restored with
//! [`from_bytes()`](store::ArchiveIndex::from_bytes) for reuse across
//! sessions.

pub(crate) mod builder;
pub mod entry;
pub mod serialize;
pub mod store;
