use crate::archive::entry::ArchiveEntry;
use crate::error::Result;

/// Events emitted by an archive parser.
#[derive(Debug)]
pub enum ArchiveEvent {
    /// A file/directory/symlink entry has been parsed.
    Entry(ArchiveEntry),
    /// The parser needs more data to make progress.
    NeedData,
    /// End of archive reached.
    EndOfArchive,
}

/// A sans-I/O incremental archive parser.
///
/// Implementations parse decompressed bytes and emit entries.
/// The caller feeds decompressed data, the parser returns
/// `(bytes_consumed, event)`. Metadata-only entries (PAX headers,
/// GNU long names, cpio trailers) are consumed internally and
/// never emitted as `ArchiveEvent::Entry`.
#[allow(dead_code)]
pub trait ArchiveParser: Send {
    /// Feed decompressed data to the parser.
    ///
    /// Returns `(bytes_consumed, event)`. The caller must advance
    /// its buffer by `bytes_consumed` before calling again.
    fn feed(&mut self, data: &[u8]) -> Result<(usize, ArchiveEvent)>;

    /// Current position in the uncompressed stream.
    fn stream_pos(&self) -> u64;
}
