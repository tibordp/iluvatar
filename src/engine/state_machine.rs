use crate::archive::detect::MIN_DETECT_BYTES;
use crate::archive::{ArchiveEvent, ArchiveFormat, ArchiveParser};
use crate::compress::CompressionFormat;
use crate::engine::checkpoint_strategy::{
    default_interval_for_format, CheckpointStrategy, FixedInterval,
};
use crate::engine::progress::IndexProgress;
use crate::engine::request::EngineRequest;
use crate::error::Result;
use crate::index::builder::IndexBuilder;
use crate::index::store::ArchiveIndex;
use crate::stream::{StreamIndexer, StreamReader, BUF_SIZE};

/// Create a boxed archive parser for the given format.
fn create_archive_parser(format: ArchiveFormat) -> Box<dyn ArchiveParser> {
    match format {
        ArchiveFormat::Tar => Box::new(crate::tar::parser::TarParser::new()),
        ArchiveFormat::Cpio => Box::new(crate::cpio::parser::CpioParser::new()),
    }
}

// ─── Indexing Engine ───

/// Linearly scans a compressed archive to build an index.
///
/// This is a sans-I/O state machine. The caller drives it by:
/// 1. Calling [`step()`](Self::step) to get the next [`EngineRequest`]
/// 2. Fulfilling the request (providing data via [`provide_data()`](Self::provide_data), etc.)
/// 3. Repeating until [`EngineRequest::Done`]
/// 4. Calling [`finish()`](Self::finish) to get the completed [`ArchiveIndex`]
///
/// Underneath, a [`StreamIndexer`] decodes the stream and lays checkpoints
/// while the tar or cpio parser reads its output for entries.
///
/// The type parameter `S` controls when decompressor checkpoints are
/// created. Use [`IndexingEngine::new`] for the format-aware default
/// ([`FixedInterval`]) or [`IndexingEngine::with_strategy`] for a
/// custom strategy.
///
/// # Example
///
/// ```
/// # fn example() -> iluvatar::Result<()> {
/// use iluvatar::{IndexingEngine, EngineRequest, CompressionFormat};
///
/// # let compressed_data: &[u8] = &[];
/// # let file_size = 0u64;
/// let mut engine = IndexingEngine::new(
///     CompressionFormat::Gzip,
///     None, // auto-detect archive format
///     file_size,
/// )?;
///
/// let mut offset = 0;
/// loop {
///     match engine.step() {
///         EngineRequest::NeedInput => {
///             if offset >= compressed_data.len() {
///                 engine.signal_eof();
///             } else {
///                 let end = (offset + 8192).min(compressed_data.len());
///                 engine.provide_data(&compressed_data[offset..end]);
///                 offset = end;
///             }
///         }
///         EngineRequest::Done => break,
///         EngineRequest::Error(e) => return Err(e),
///         _ => {}
///     }
/// }
///
/// let index = engine.finish();
/// # Ok(())
/// # }
/// ```
pub struct IndexingEngine<S: CheckpointStrategy = FixedInterval> {
    indexer: StreamIndexer<S>,
    archive_parser: Option<Box<dyn ArchiveParser>>,
    index_builder: IndexBuilder,
    /// Buffer for archive format auto-detection.
    detect_buf: Vec<u8>,
    /// Scratch for draining indexer output into the parser.
    chunk: Vec<u8>,
    done: bool,
}

impl IndexingEngine<FixedInterval> {
    /// Create a new indexing engine with the default checkpoint strategy
    /// for the given compression format.
    ///
    /// Uses [`FixedInterval`] with a format-aware interval:
    /// 1 MiB for bzip2, 16 MiB for gzip, 64 MiB for zstd/xz.
    ///
    /// `compression` - compression format of the archive
    /// `archive_format` - archive container format, or `None` to auto-detect
    /// `archive_size` - total size of the compressed archive (for index metadata)
    pub fn new(
        compression: CompressionFormat,
        archive_format: Option<ArchiveFormat>,
        archive_size: u64,
    ) -> Result<Self> {
        Self::with_strategy(
            compression,
            archive_format,
            FixedInterval::new(default_interval_for_format(compression)),
            archive_size,
        )
    }
}

impl<S: CheckpointStrategy> IndexingEngine<S> {
    /// Create a new indexing engine with a custom checkpoint strategy.
    ///
    /// `compression` - compression format of the archive
    /// `archive_format` - archive container format, or `None` to auto-detect
    /// `strategy` - controls when decompressor checkpoints are created
    /// `archive_size` - total size of the compressed archive (for index metadata)
    pub fn with_strategy(
        compression: CompressionFormat,
        archive_format: Option<ArchiveFormat>,
        strategy: S,
        archive_size: u64,
    ) -> Result<Self> {
        let compressed_len = if archive_size == 0 {
            None
        } else {
            Some(archive_size)
        };
        let mut indexer = StreamIndexer::new(compression.into(), strategy, compressed_len)?;
        indexer.emit_output(true);
        let (parser, detect_buf) = match archive_format {
            Some(af) => (Some(create_archive_parser(af)), Vec::new()),
            None => (None, Vec::with_capacity(MIN_DETECT_BYTES)),
        };
        Ok(Self {
            indexer,
            archive_parser: parser,
            index_builder: IndexBuilder::new(
                compression,
                archive_format.unwrap_or(ArchiveFormat::Tar),
                archive_size,
            ),
            detect_buf,
            chunk: vec![0; BUF_SIZE],
            done: false,
        })
    }

    /// Drive the state machine forward. Returns what the engine needs next.
    pub fn step(&mut self) -> EngineRequest {
        loop {
            if self.done {
                return EngineRequest::Done;
            }
            match self.indexer.step() {
                EngineRequest::OutputReady => {
                    if let Err(e) = self.drain_output() {
                        return EngineRequest::Error(e);
                    }
                }
                EngineRequest::Done => {
                    self.done = true;
                    return EngineRequest::Done;
                }
                other => return other,
            }
        }
    }

    /// Feed the indexer's pending output through detection and the parser.
    fn drain_output(&mut self) -> Result<()> {
        loop {
            let n = self.indexer.read_output(&mut self.chunk);
            if n == 0 {
                return Ok(());
            }
            let mut data: &[u8] = &self.chunk[..n];
            if self.archive_parser.is_none() {
                self.detect_buf.extend_from_slice(data);
                match crate::archive::detect::detect_archive_format(&self.detect_buf) {
                    Some(af) => {
                        self.archive_parser = Some(create_archive_parser(af));
                        self.index_builder.set_archive_format(af);
                        // Replay the detection bytes through the parser.
                        let detect = std::mem::take(&mut self.detect_buf);
                        self.feed_to_parser(&detect)?;
                        if self.done {
                            return Ok(());
                        }
                        continue;
                    }
                    None => continue,
                }
            }
            if self.done {
                // Past the archive trailer: the rest of the stream is
                // padding the parser must not see.
                continue;
            }
            let chunk = std::mem::take(&mut self.chunk);
            data = &chunk[..n];
            let result = self.feed_to_parser(data);
            self.chunk = chunk;
            result?;
        }
    }

    /// Feed decompressed data to the archive parser.
    fn feed_to_parser(&mut self, data: &[u8]) -> Result<()> {
        let parser = self.archive_parser.as_mut().unwrap();
        let mut parse_offset = 0;

        while parse_offset < data.len() {
            let (consumed, event) = parser.feed(&data[parse_offset..])?;
            parse_offset += consumed;
            match event {
                ArchiveEvent::Entry(entry) => {
                    self.index_builder.add_entry(entry);
                }
                ArchiveEvent::NeedData => {
                    if consumed == 0 {
                        break;
                    }
                }
                ArchiveEvent::EndOfArchive => {
                    self.done = true;
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    /// Provide compressed data to the engine.
    ///
    /// Call this after [`step()`](Self::step) returns [`EngineRequest::NeedInput`].
    /// The engine copies the data internally, so the caller's buffer can be reused.
    pub fn provide_data(&mut self, data: &[u8]) {
        self.indexer.provide_data(data);
    }

    /// Signal that the end of the compressed stream has been reached.
    ///
    /// Call this instead of [`provide_data()`](Self::provide_data) when
    /// the reader returns zero bytes (EOF). The engine may still need
    /// a few more [`step()`](Self::step) calls to drain internally
    /// buffered output.
    pub fn signal_eof(&mut self) {
        self.indexer.signal_eof();
    }

    /// Consume the engine and return the completed index.
    ///
    /// Call this after [`step()`](Self::step) returns [`EngineRequest::Done`].
    pub fn finish(self) -> ArchiveIndex {
        self.index_builder.finish(self.indexer.finish(), true)
    }

    /// Return a snapshot of the current indexing progress.
    ///
    /// Cheap to call between any two `step()` calls.
    pub fn progress(&self) -> IndexProgress {
        let stream = self.indexer.progress();
        IndexProgress {
            compressed_bytes_processed: stream.compressed_pos,
            compressed_bytes_total: stream.compressed_len.unwrap_or(0),
            uncompressed_bytes_processed: stream.unpacked_pos,
            entries_found: self.index_builder.entry_count(),
            checkpoints_created: stream.checkpoints,
            checkpoint_data_bytes: stream.checkpoint_data_bytes,
            last_entry_path: self.index_builder.last_entry_path().map(|s| s.to_owned()),
            is_complete: self.done,
        }
    }

    /// Snapshot the current state as a usable partial index.
    ///
    /// The returned `ArchiveIndex` contains all entries and checkpoints
    /// discovered so far and can be used with `ReadEngine` to read
    /// any file that has been indexed. Its `metadata.complete` field
    /// will be `false`.
    ///
    /// The engine continues to be usable for further indexing.
    pub fn snapshot_index(&self) -> ArchiveIndex {
        self.index_builder.snapshot(self.indexer.snapshot())
    }

    /// Cancel indexing and return whatever index has been built so far.
    ///
    /// Like `finish()`, this consumes the engine. Unlike `finish()`,
    /// the returned index has `metadata.complete = false`.
    pub fn cancel(self) -> ArchiveIndex {
        self.index_builder.finish(self.indexer.finish(), false)
    }
}

// ─── Read Engine ───

/// Reads a specific file from a compressed archive using an index.
///
/// A [`StreamReader`] aimed at the file's unpacked range. Sans-I/O: the
/// caller provides compressed data when requested and reads decompressed
/// output when available.
///
/// The read loop follows the same pattern as [`IndexingEngine`], but with
/// the addition of [`EngineRequest::SeekAndRead`] (which asks the caller
/// to seek in the compressed stream) and [`EngineRequest::OutputReady`]
/// (which signals decompressed file data is available via
/// [`read_output()`](Self::read_output)).
///
/// # Example
///
/// ```
/// # fn example(index: &iluvatar::ArchiveIndex, compressed: &[u8]) -> iluvatar::Result<Vec<u8>> {
/// use iluvatar::{ReadEngine, EngineRequest};
///
/// let mut engine = ReadEngine::new(index, "path/to/file.txt")?;
/// let mut result = Vec::new();
/// let mut offset = 0;
///
/// loop {
///     match engine.step() {
///         EngineRequest::NeedInput => {
///             if offset >= compressed.len() {
///                 engine.signal_eof();
///             } else {
///                 let end = (offset + 8192).min(compressed.len());
///                 engine.provide_data(&compressed[offset..end]);
///                 offset = end;
///             }
///         }
///         EngineRequest::SeekAndRead { offset: off, len } => {
///             let start = off as usize;
///             let end = (start + len).min(compressed.len());
///             engine.provide_data(&compressed[start..end]);
///             offset = end;
///         }
///         EngineRequest::OutputReady => {
///             let mut buf = [0u8; 8192];
///             loop {
///                 let n = engine.read_output(&mut buf);
///                 if n == 0 { break; }
///                 result.extend_from_slice(&buf[..n]);
///             }
///         }
///         EngineRequest::Done => break,
///         EngineRequest::Error(e) => return Err(e),
///     }
/// }
/// # Ok(result)
/// # }
/// ```
pub struct ReadEngine(StreamReader);

impl ReadEngine {
    /// Create a read engine for a specific file.
    ///
    /// Looks up the file in the index and prepares to read it.
    pub fn new(index: &ArchiveIndex, path: &str) -> Result<Self> {
        let entry = index
            .get(path)
            .ok_or_else(|| crate::error::Error::FileNotFound(path.into()))?;
        Ok(Self(StreamReader::new(
            &index.stream,
            entry.uncompressed_offset,
            entry.size,
        )?))
    }

    /// Create a read engine for a byte range within a file.
    ///
    /// Reads `len` bytes starting at byte `file_offset` within the file.
    /// Seeks to the best checkpoint for that position — for a 10 GB file,
    /// reading at offset 9 GB will seek to a checkpoint near 9 GB, not
    /// decompress from the file's start.
    ///
    /// `file_offset` and `len` are clamped to the file's size.
    /// If `file_offset >= file size`, the engine completes immediately
    /// with zero output.
    pub fn new_range(index: &ArchiveIndex, path: &str, file_offset: u64, len: u64) -> Result<Self> {
        let entry = index
            .get(path)
            .ok_or_else(|| crate::error::Error::FileNotFound(path.into()))?;
        let file_offset = file_offset.min(entry.size);
        let read_len = len.min(entry.size - file_offset);
        Ok(Self(StreamReader::new(
            &index.stream,
            entry.uncompressed_offset + file_offset,
            read_len,
        )?))
    }

    /// Drive the state machine forward.
    pub fn step(&mut self) -> EngineRequest {
        self.0.step()
    }

    /// Provide compressed data to the engine.
    ///
    /// Call this after [`step()`](Self::step) returns [`EngineRequest::NeedInput`]
    /// or [`EngineRequest::SeekAndRead`]. For `SeekAndRead`, seek to the
    /// requested offset first, then provide the bytes read from that position.
    pub fn provide_data(&mut self, data: &[u8]) {
        self.0.provide_data(data)
    }

    /// Signal that the end of the compressed stream has been reached.
    ///
    /// Call this instead of [`provide_data()`](Self::provide_data) when
    /// the reader returns zero bytes.
    pub fn signal_eof(&mut self) {
        self.0.signal_eof()
    }

    /// Read decompressed output from the engine.
    /// Returns the number of bytes written to `buf`.
    pub fn read_output(&mut self, buf: &mut [u8]) -> usize {
        self.0.read_output(buf)
    }

    /// The underlying stream reader, for retargeting with
    /// [`StreamReader::seek_forward`].
    pub fn stream_reader(&mut self) -> &mut StreamReader {
        &mut self.0
    }

    /// Unwrap into the stream reader.
    pub fn into_stream_reader(self) -> StreamReader {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::CompressionFormat;

    /// Helper: drive indexing engine with in-memory data.
    fn index_from_bytes(data: &[u8], format: CompressionFormat) -> ArchiveIndex {
        let mut engine = IndexingEngine::new(format, None, data.len() as u64).unwrap();
        let mut offset = 0;
        let chunk_size = 8192;

        loop {
            match engine.step() {
                EngineRequest::NeedInput => {
                    if offset >= data.len() {
                        engine.signal_eof();
                    } else {
                        let end = (offset + chunk_size).min(data.len());
                        engine.provide_data(&data[offset..end]);
                        offset = end;
                    }
                }
                EngineRequest::Done => break,
                EngineRequest::Error(e) => panic!("indexing error: {}", e),
                _ => {}
            }
        }

        engine.finish()
    }

    /// Helper: read a file from in-memory compressed archive using read engine.
    fn read_file_from_bytes(data: &[u8], index: &ArchiveIndex, path: &str) -> Vec<u8> {
        let mut engine = ReadEngine::new(index, path).unwrap();
        let mut result = Vec::new();
        let mut offset = 0;
        let chunk_size = 8192;

        loop {
            match engine.step() {
                EngineRequest::NeedInput => {
                    if offset >= data.len() {
                        engine.signal_eof();
                    } else {
                        let end = (offset + chunk_size).min(data.len());
                        engine.provide_data(&data[offset..end]);
                        offset = end;
                    }
                }
                EngineRequest::SeekAndRead { offset: off, len } => {
                    let start = off as usize;
                    let end = (start + len).min(data.len());
                    if start >= data.len() {
                        engine.signal_eof();
                    } else {
                        engine.provide_data(&data[start..end]);
                    }
                }
                EngineRequest::OutputReady => {
                    let mut buf = vec![0u8; 65536];
                    let n = engine.read_output(&mut buf);
                    result.extend_from_slice(&buf[..n]);
                }
                EngineRequest::Done => break,
                EngineRequest::Error(e) => panic!("read error: {}", e),
            }
        }

        result
    }

    #[test]
    fn test_index_uncompressed_tar() {
        // Create a simple tar in memory using our test helper
        let tar_data = create_test_tar_multi(&[
            ("file1.txt", b"Hello from file 1!"),
            ("file2.txt", b"Hello from file 2!"),
        ]);

        let index = index_from_bytes(&tar_data, CompressionFormat::None);
        assert_eq!(index.entries.len(), 2);
        assert!(index.get("file1.txt").is_some());
        assert!(index.get("file2.txt").is_some());
        assert_eq!(index.get("file1.txt").unwrap().size, 18);
        assert_eq!(index.get("file2.txt").unwrap().size, 18);
    }

    #[test]
    fn test_read_uncompressed_tar() {
        let tar_data = create_test_tar_multi(&[
            ("file1.txt", b"Hello from file 1!"),
            ("file2.txt", b"Content of file two."),
        ]);

        let index = index_from_bytes(&tar_data, CompressionFormat::None);

        let content1 = read_file_from_bytes(&tar_data, &index, "file1.txt");
        assert_eq!(&content1, b"Hello from file 1!");

        let content2 = read_file_from_bytes(&tar_data, &index, "file2.txt");
        assert_eq!(&content2, b"Content of file two.");
    }

    /// Create a tar archive with multiple files.
    fn create_test_tar_multi(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut archive = Vec::new();

        for (filename, content) in files {
            let mut header = [0u8; 512];
            let name_bytes = filename.as_bytes();
            header[..name_bytes.len()].copy_from_slice(name_bytes);
            header[100..108].copy_from_slice(b"0000644\0");
            header[108..116].copy_from_slice(b"0001000\0");
            header[116..124].copy_from_slice(b"0001000\0");
            let size_str = format!("{:011o}\0", content.len());
            header[124..136].copy_from_slice(size_str.as_bytes());
            header[136..148].copy_from_slice(b"14267657570\0");
            header[156] = b'0';
            header[257..262].copy_from_slice(b"ustar");
            header[263..265].copy_from_slice(b"00");

            // Checksum
            header[148..156].copy_from_slice(b"        ");
            let checksum: u32 = header.iter().map(|&b| b as u32).sum();
            let checksum_str = format!("{:06o}\0 ", checksum);
            header[148..156].copy_from_slice(checksum_str.as_bytes());

            archive.extend_from_slice(&header);
            archive.extend_from_slice(content);
            let padding = (512 - (content.len() % 512)) % 512;
            archive.extend(std::iter::repeat(0u8).take(padding));
        }

        // Two zero blocks for end-of-archive
        archive.extend(std::iter::repeat(0u8).take(1024));
        archive
    }
}
