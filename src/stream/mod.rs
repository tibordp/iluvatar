//! Random access into one compressed stream, whatever it contains.
//!
//! The stream layer knows nothing about tar, cpio or any other container.
//! A [`StreamIndex`] is the checkpoint table of one stream;
//! a [`StreamIndexer`] lays checkpoints while decoding forward, in one pass
//! or in resumable increments; a [`StreamReader`] decodes an unpacked byte
//! range by restoring the nearest checkpoint. The tar and cpio engines in
//! [`engine`](crate::engine) are compositions of these, and a container
//! that already knows where its members live (a bare `.gz`, a 7z folder)
//! uses them directly.

pub mod index;
pub mod indexer;
pub mod progress;
pub mod reader;

pub use index::StreamIndex;
pub use indexer::StreamIndexer;
pub use progress::StreamProgress;
pub use reader::StreamReader;

/// Decoded bytes handled per engine step.
pub(crate) const BUF_SIZE: usize = 64 * 1024;
