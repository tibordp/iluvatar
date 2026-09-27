use crate::archive::entry::ArchiveEntry;
use crate::error::Result;

/// Events emitted by an archive parser.
#[derive(Debug)]
pub enum ArchiveEvent {
    /// A file/directory/symlink entry has been parsed.
    Entry(ArchiveEntry),
    /// The parser needs more data to make progress.
    NeedData,
    /// End-of-archive marker reached (tar zero blocks, cpio trailer). ar
    /// has no marker and never emits this; see `ArchiveParser::end_of_stream`.
    EndOfArchive,
}

/// A sans-I/O incremental archive parser.
///
/// Implementations parse decompressed bytes and emit entries.
/// The caller feeds decompressed data, the parser returns
/// `(bytes_consumed, event)`. Metadata-only members (PAX headers,
/// GNU long names, cpio trailers, ar symbol and long-name tables) are
/// consumed internally and never emitted as `ArchiveEvent::Entry`.
#[allow(dead_code)]
pub trait ArchiveParser: Send {
    /// Feed decompressed data to the parser.
    ///
    /// Returns `(bytes_consumed, event)`. The caller must advance
    /// its buffer by `bytes_consumed` before calling again.
    fn feed(&mut self, data: &[u8]) -> Result<(usize, ArchiveEvent)>;

    /// Current position in the uncompressed stream.
    fn stream_pos(&self) -> u64;

    /// Called when the stream ends before the parser reported
    /// `EndOfArchive`. Returns [`Error::TruncatedArchive`] if the stream
    /// stopped somewhere a well-formed archive cannot end (inside a
    /// header, inside a member's data, before a required trailer).
    ///
    /// [`Error::TruncatedArchive`]: crate::Error::TruncatedArchive
    fn end_of_stream(&self) -> Result<()>;
}
