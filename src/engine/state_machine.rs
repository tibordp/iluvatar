use crate::archive::detect::MIN_DETECT_BYTES;
use crate::archive::{ArchiveEvent, ArchiveFormat, ArchiveParser};
use crate::compress::checkpoint::{Checkpoint, CheckpointState};
use crate::compress::decompressor::{DecompressStatus, Decompressor};
use crate::compress::CompressionFormat;
use crate::engine::progress::IndexProgress;
use crate::engine::request::EngineRequest;
use crate::error::{Result, Error};
use crate::index::builder::IndexBuilder;
use crate::index::store::ArchiveIndex;

/// Default checkpoint interval: 1 MiB of uncompressed data.
pub const DEFAULT_CHECKPOINT_INTERVAL: u64 = 1024 * 1024;

/// Default buffer size for decompression.
const DECOMPRESS_BUF_SIZE: usize = 64 * 1024;

// ─── Factory for creating decompressors ───

/// Create a boxed decompressor for the given format.
fn create_decompressor(format: CompressionFormat) -> Result<Box<dyn Decompressor>> {
    match format {
        CompressionFormat::None => Ok(Box::new(crate::compress::none::NoneDecompressor::new())),

        #[cfg(feature = "gzip")]
        CompressionFormat::Gzip => Ok(Box::new(crate::compress::gzip::GzipDecompressor::new())),

        #[cfg(feature = "bz2")]
        CompressionFormat::Bzip2 => Ok(Box::new(
            crate::compress::bzip2::Bzip2Decompressor::new(),
        )),

        #[cfg(feature = "xz")]
        CompressionFormat::Xz => Ok(Box::new(
            crate::compress::xz::XzDecompressor::new(),
        )),

        #[cfg(feature = "zstandard")]
        CompressionFormat::Zstd => Ok(Box::new(
            crate::compress::zstd_dec::ZstdDecompressor::new(),
        )),

        #[allow(unreachable_patterns)]
        _ => Err(Error::UnsupportedFormat),
    }
}

/// Create a boxed archive parser for the given format.
fn create_archive_parser(format: ArchiveFormat) -> Box<dyn ArchiveParser> {
    match format {
        ArchiveFormat::Tar => Box::new(crate::tar::parser::TarParser::new()),
        ArchiveFormat::Cpio => Box::new(crate::cpio::parser::CpioParser::new()),
    }
}

// ─── Indexing Engine ───

/// State of the indexing engine.
enum IndexingState {
    /// Waiting for compressed input data.
    NeedInput,
    /// Processing data (decompressing + parsing).
    Processing,
    /// Completed.
    Done,
}

/// Linearly scans a compressed archive to build an index.
///
/// This is a sans-I/O state machine. The caller drives it by:
/// 1. Calling `step()` to get the next request
/// 2. Fulfilling the request (providing data, etc.)
/// 3. Repeating until `Done`
pub struct IndexingEngine {
    decompressor: Box<dyn Decompressor>,
    archive_parser: Option<Box<dyn ArchiveParser>>,
    archive_format: Option<ArchiveFormat>,
    index_builder: IndexBuilder,
    /// Buffer for archive format auto-detection.
    detect_buf: Vec<u8>,
    checkpoint_interval: u64,
    compression: CompressionFormat,
    compressed_pos: u64,
    uncompressed_pos: u64,
    last_checkpoint_pos: u64,
    archive_size: u64,
    state: IndexingState,
    /// Compressed input buffer (data provided by caller).
    input_buf: Vec<u8>,
    input_pos: usize,
    /// Decompressed output buffer (fed to archive parser).
    decompress_buf: Vec<u8>,
    eof: bool,
}

impl IndexingEngine {
    /// Create a new indexing engine.
    ///
    /// `compression` - compression format of the archive
    /// `archive_format` - archive container format, or `None` to auto-detect
    /// `checkpoint_interval` - bytes of uncompressed data between checkpoints
    /// `archive_size` - total size of the compressed archive (for index metadata)
    pub fn new(
        compression: CompressionFormat,
        archive_format: Option<ArchiveFormat>,
        checkpoint_interval: u64,
        archive_size: u64,
    ) -> Result<Self> {
        let decompressor = create_decompressor(compression)?;

        let (parser, builder, detect_buf) = if let Some(af) = archive_format {
            let parser = create_archive_parser(af);
            let mut builder = IndexBuilder::new(compression, af, archive_size);
            builder.add_checkpoint(Checkpoint {
                compressed_offset: 0,
                bit_offset: 0,
                uncompressed_offset: 0,
                state: CheckpointState::None,
            });
            (Some(parser), Some(builder), Vec::new())
        } else {
            (None, None, Vec::with_capacity(MIN_DETECT_BYTES))
        };

        Ok(Self {
            decompressor,
            archive_parser: parser,
            archive_format,
            index_builder: builder.unwrap_or_else(|| {
                // Placeholder; will be replaced after detection.
                IndexBuilder::new(compression, ArchiveFormat::Tar, archive_size)
            }),
            detect_buf,
            checkpoint_interval,
            compression,
            compressed_pos: 0,
            uncompressed_pos: 0,
            last_checkpoint_pos: 0,
            archive_size,
            state: IndexingState::NeedInput,
            input_buf: Vec::new(),
            input_pos: 0,
            decompress_buf: vec![0u8; DECOMPRESS_BUF_SIZE],
            eof: false,
        })
    }

    /// Drive the state machine forward. Returns what the engine needs next.
    pub fn step(&mut self) -> EngineRequest {
        match self.state {
            IndexingState::Done => return EngineRequest::Done,
            IndexingState::NeedInput => {
                if self.eof {
                    self.state = IndexingState::Done;
                    return EngineRequest::Done;
                }
                return EngineRequest::NeedInput;
            }
            IndexingState::Processing => {}
        }

        // We have data to process — decompress and parse
        let input = if self.input_pos < self.input_buf.len() {
            &self.input_buf[self.input_pos..]
        } else if self.eof {
            &[]
        } else {
            self.state = IndexingState::NeedInput;
            return EngineRequest::NeedInput;
        };

        let result = match self.decompressor.decompress(input, &mut self.decompress_buf) {
            Ok(r) => r,
            Err(e) => return EngineRequest::Error(e),
        };

        self.input_pos += result.bytes_consumed;
        self.compressed_pos += result.bytes_consumed as u64;

        if result.bytes_produced > 0 {
            self.uncompressed_pos += result.bytes_produced as u64;

            // Auto-detect archive format if not yet known
            if self.archive_parser.is_none() {
                self.detect_buf
                    .extend_from_slice(&self.decompress_buf[..result.bytes_produced]);

                if let Some(af) = crate::archive::detect::detect_archive_format(&self.detect_buf) {
                    self.archive_format = Some(af);
                    self.archive_parser = Some(create_archive_parser(af));
                    self.index_builder =
                        IndexBuilder::new(self.compression, af, self.archive_size);
                    self.index_builder.add_checkpoint(Checkpoint {
                        compressed_offset: 0,
                        bit_offset: 0,
                        uncompressed_offset: 0,
                        state: CheckpointState::None,
                    });

                    // Feed accumulated detection bytes to the parser
                    let detect_data = std::mem::take(&mut self.detect_buf);
                    if let Err(e) = self.feed_to_parser(&detect_data) {
                        return EngineRequest::Error(e);
                    }
                }
                // Not enough data yet — continue decompressing
            } else {
                // Check if we should take a checkpoint
                if self.uncompressed_pos - self.last_checkpoint_pos >= self.checkpoint_interval {
                    match self
                        .decompressor
                        .checkpoint(self.compressed_pos, self.uncompressed_pos)
                    {
                        Ok(cp) => {
                            self.index_builder.add_checkpoint(cp);
                            self.last_checkpoint_pos = self.uncompressed_pos;
                        }
                        Err(e) => return EngineRequest::Error(e),
                    }
                }

                // Feed decompressed data to archive parser.
                // We need to copy the slice to avoid a borrow conflict
                // (feed_to_parser needs &mut self while decompress_buf is &self).
                let bytes_produced = result.bytes_produced;
                if let Err(e) = self.feed_to_parser_from_buf(bytes_produced) {
                    return EngineRequest::Error(e);
                }
            }

            if matches!(self.state, IndexingState::Done) {
                return EngineRequest::Done;
            }
        }

        if result.status == DecompressStatus::StreamEnd {
            self.state = IndexingState::Done;
            return EngineRequest::Done;
        }

        // If we consumed all input, need more
        if self.input_pos >= self.input_buf.len() {
            if self.eof {
                // Only stop if the decompressor made no progress at all.
                // It may have internally buffered output that needs draining.
                if result.bytes_consumed == 0 && result.bytes_produced == 0 {
                    self.state = IndexingState::Done;
                    EngineRequest::Done
                } else {
                    // Keep processing to drain buffered output
                    EngineRequest::NeedInput
                }
            } else {
                self.state = IndexingState::NeedInput;
                EngineRequest::NeedInput
            }
        } else {
            // Still have unconsumed input — keep processing.
            // (Returning NeedInput here would cause the caller to overwrite
            //  unconsumed bytes via provide_data.)
            self.step()
        }
    }

    /// Feed decompressed data from `self.decompress_buf[..len]` to the archive parser.
    fn feed_to_parser_from_buf(&mut self, len: usize) -> Result<()> {
        let parser = self.archive_parser.as_mut().unwrap();
        let mut parse_offset = 0;

        while parse_offset < len {
            let data = &self.decompress_buf[parse_offset..len];
            let (consumed, event) = parser.feed(data)?;
            parse_offset += consumed;
            match event {
                ArchiveEvent::Entry(entry) => {
                    let cp_idx = self.index_builder.checkpoint_count().saturating_sub(1);
                    self.index_builder.add_entry(entry, cp_idx);
                }
                ArchiveEvent::NeedData => {
                    if consumed == 0 {
                        break;
                    }
                }
                ArchiveEvent::EndOfArchive => {
                    self.state = IndexingState::Done;
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    /// Feed arbitrary decompressed data to the archive parser.
    fn feed_to_parser(&mut self, data: &[u8]) -> Result<()> {
        let parser = self.archive_parser.as_mut().unwrap();
        let mut parse_offset = 0;

        while parse_offset < data.len() {
            let (consumed, event) = parser.feed(&data[parse_offset..])?;
            parse_offset += consumed;
            match event {
                ArchiveEvent::Entry(entry) => {
                    let cp_idx = self.index_builder.checkpoint_count().saturating_sub(1);
                    self.index_builder.add_entry(entry, cp_idx);
                }
                ArchiveEvent::NeedData => {
                    if consumed == 0 {
                        break;
                    }
                }
                ArchiveEvent::EndOfArchive => {
                    self.state = IndexingState::Done;
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    /// Provide compressed data to the engine.
    pub fn provide_data(&mut self, data: &[u8]) {
        self.input_buf.clear();
        self.input_buf.extend_from_slice(data);
        self.input_pos = 0;
        self.state = IndexingState::Processing;
    }

    /// Signal that we've reached the end of the compressed stream.
    pub fn signal_eof(&mut self) {
        self.eof = true;
        self.state = IndexingState::Processing;
    }

    /// Consume the engine and return the built index.
    pub fn finish(self) -> ArchiveIndex {
        self.index_builder.finish(self.uncompressed_pos)
    }

    /// Return a snapshot of the current indexing progress.
    ///
    /// Cheap to call between any two `step()` calls.
    pub fn progress(&self) -> IndexProgress {
        IndexProgress {
            compressed_bytes_processed: self.compressed_pos,
            compressed_bytes_total: self.index_builder.archive_size(),
            uncompressed_bytes_processed: self.uncompressed_pos,
            entries_found: self.index_builder.entry_count(),
            checkpoints_created: self.index_builder.checkpoint_count(),
            last_entry_path: self.index_builder.last_entry_path().map(|s| s.to_owned()),
            is_complete: matches!(self.state, IndexingState::Done),
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
        self.index_builder.snapshot(self.uncompressed_pos)
    }

    /// Cancel indexing and return whatever index has been built so far.
    ///
    /// Like `finish()`, this consumes the engine. Unlike `finish()`,
    /// the returned index has `metadata.complete = false`.
    pub fn cancel(self) -> ArchiveIndex {
        self.index_builder.finish_partial(self.uncompressed_pos)
    }
}

// ─── Read Engine ───

/// State of the read engine.
#[derive(Debug)]
enum ReadState {
    /// Need to seek to checkpoint and read compressed data.
    SeekToCheckpoint,
    /// Decompressing and skipping until we reach the target file.
    DecompressingToTarget { skip_remaining: u64 },
    /// Emitting target file data.
    EmittingData { data_remaining: u64 },
    /// Need more compressed input.
    NeedInput { skip_remaining: u64 },
    /// Need more compressed input while emitting.
    NeedInputEmitting { data_remaining: u64 },
    /// Done.
    Done,
}

/// Reads a specific file from a compressed tar archive using an index.
///
/// Sans-I/O: the caller provides compressed data when requested,
/// and reads decompressed output when available.
pub struct ReadEngine {
    decompressor: Box<dyn Decompressor>,
    checkpoint: Checkpoint,
    target_offset: u64,
    target_size: u64,
    state: ReadState,
    /// Decompressed output buffer.
    output_buf: Vec<u8>,
    /// How many valid bytes are in output_buf.
    output_len: usize,
    /// How many bytes have been read from output_buf by the caller.
    output_read: usize,
    /// Compressed input buffer.
    input_buf: Vec<u8>,
    input_pos: usize,
    /// Current uncompressed position.
    uncompressed_pos: u64,
    eof: bool,
}

impl ReadEngine {
    /// Create a read engine for a specific file.
    ///
    /// Looks up the file in the index and prepares to read it.
    pub fn new(index: &ArchiveIndex, path: &str) -> Result<Self> {
        let entry = index
            .get(path)
            .ok_or_else(|| Error::FileNotFound(path.into()))?;

        let target_offset = entry.uncompressed_offset;
        let target_size = entry.size;
        let (_, checkpoint) = index.best_checkpoint_for_offset(target_offset);
        let checkpoint = checkpoint.clone();
        let decompressor = create_decompressor(index.metadata.compression)?;

        Ok(Self {
            decompressor,
            checkpoint,
            target_offset,
            target_size,
            state: ReadState::SeekToCheckpoint,
            output_buf: vec![0u8; DECOMPRESS_BUF_SIZE],
            output_len: 0,
            output_read: 0,
            input_buf: Vec::new(),
            input_pos: 0,
            uncompressed_pos: 0,
            eof: false,
        })
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
    pub fn new_range(
        index: &ArchiveIndex,
        path: &str,
        file_offset: u64,
        len: u64,
    ) -> Result<Self> {
        let entry = index
            .get(path)
            .ok_or_else(|| Error::FileNotFound(path.into()))?;

        let file_offset = file_offset.min(entry.size);
        let read_len = len.min(entry.size - file_offset);

        if read_len == 0 {
            let decompressor = create_decompressor(index.metadata.compression)?;
            return Ok(Self {
                decompressor,
                checkpoint: index.checkpoints[0].clone(),
                target_offset: 0,
                target_size: 0,
                state: ReadState::Done,
                output_buf: vec![0u8; DECOMPRESS_BUF_SIZE],
                output_len: 0,
                output_read: 0,
                input_buf: Vec::new(),
                input_pos: 0,
                uncompressed_pos: 0,
                eof: false,
            });
        }

        let abs_offset = entry.uncompressed_offset + file_offset;
        let (_, checkpoint) = index.best_checkpoint_for_offset(abs_offset);
        let decompressor = create_decompressor(index.metadata.compression)?;

        Ok(Self {
            decompressor,
            checkpoint: checkpoint.clone(),
            target_offset: abs_offset,
            target_size: read_len,
            state: ReadState::SeekToCheckpoint,
            output_buf: vec![0u8; DECOMPRESS_BUF_SIZE],
            output_len: 0,
            output_read: 0,
            input_buf: Vec::new(),
            input_pos: 0,
            uncompressed_pos: 0,
            eof: false,
        })
    }

    /// Drive the state machine forward.
    pub fn step(&mut self) -> EngineRequest {
        match &self.state {
            ReadState::SeekToCheckpoint => {
                // Restore decompressor from checkpoint
                if let Err(e) = self.decompressor.restore(&self.checkpoint) {
                    return EngineRequest::Error(e);
                }

                // Determine actual start position and skip amount.
                // All formats now support mid-stream resume via checkpoints.
                let compressed_start = self.checkpoint.compressed_offset;
                self.uncompressed_pos = self.checkpoint.uncompressed_offset;
                let skip = self
                    .target_offset
                    .saturating_sub(self.checkpoint.uncompressed_offset);

                self.state = if skip > 0 {
                    ReadState::NeedInput {
                        skip_remaining: skip,
                    }
                } else if self.target_size > 0 {
                    ReadState::NeedInputEmitting {
                        data_remaining: self.target_size,
                    }
                } else {
                    ReadState::Done
                };

                if compressed_start == 0 {
                    EngineRequest::NeedInput
                } else {
                    EngineRequest::SeekAndRead {
                        offset: compressed_start,
                        len: DECOMPRESS_BUF_SIZE,
                    }
                }
            }

            ReadState::NeedInput { skip_remaining } => {
                let skip = *skip_remaining;
                if self.eof {
                    // Even at EOF, try decompressing — the decompressor may
                    // have internal buffered data (e.g., gzip pending).
                    self.state = ReadState::DecompressingToTarget {
                        skip_remaining: skip,
                    };
                    return self.decompress_and_skip(skip);
                }
                EngineRequest::NeedInput
            }
            ReadState::NeedInputEmitting { data_remaining } => {
                let rem = *data_remaining;
                if self.eof {
                    self.state = ReadState::EmittingData {
                        data_remaining: rem,
                    };
                    return self.decompress_and_emit(rem);
                }
                EngineRequest::NeedInput
            }

            ReadState::DecompressingToTarget { skip_remaining } => {
                let skip_remaining = *skip_remaining;
                self.decompress_and_skip(skip_remaining)
            }

            ReadState::EmittingData { data_remaining } => {
                let data_remaining = *data_remaining;
                self.decompress_and_emit(data_remaining)
            }

            ReadState::Done => EngineRequest::Done,
        }
    }

    /// Provide compressed data to the engine.
    pub fn provide_data(&mut self, data: &[u8]) {
        self.input_buf.clear();
        self.input_buf.extend_from_slice(data);
        self.input_pos = 0;

        match &self.state {
            ReadState::NeedInput { skip_remaining } => {
                let skip = *skip_remaining;
                self.state = ReadState::DecompressingToTarget {
                    skip_remaining: skip,
                };
            }
            ReadState::NeedInputEmitting { data_remaining } => {
                let rem = *data_remaining;
                self.state = ReadState::EmittingData {
                    data_remaining: rem,
                };
            }
            _ => {}
        }
    }

    /// Signal end of compressed input.
    pub fn signal_eof(&mut self) {
        self.eof = true;
    }

    /// Read decompressed output from the engine.
    /// Returns the number of bytes written to `buf`.
    pub fn read_output(&mut self, buf: &mut [u8]) -> usize {
        let available = self.output_len - self.output_read;
        if available == 0 {
            return 0;
        }
        let n = available.min(buf.len());
        buf[..n].copy_from_slice(&self.output_buf[self.output_read..self.output_read + n]);
        self.output_read += n;
        if self.output_read >= self.output_len {
            self.output_len = 0;
            self.output_read = 0;
        }
        n
    }

    fn decompress_and_skip(&mut self, mut skip_remaining: u64) -> EngineRequest {
        let input = &self.input_buf[self.input_pos..];
        let had_input = !input.is_empty();
        let mut temp_buf = vec![0u8; DECOMPRESS_BUF_SIZE];
        match self.decompressor.decompress(input, &mut temp_buf) {
            Ok(result) => {
                self.input_pos += result.bytes_consumed;
                let produced = result.bytes_produced as u64;
                self.uncompressed_pos += produced;

                if produced > 0 && produced <= skip_remaining {
                    skip_remaining -= produced;
                    if skip_remaining == 0 {
                        if self.target_size > 0 {
                            self.state = ReadState::EmittingData {
                                data_remaining: self.target_size,
                            };
                        } else {
                            self.state = ReadState::Done;
                            return EngineRequest::Done;
                        }
                    } else {
                        self.state = ReadState::DecompressingToTarget { skip_remaining };
                    }
                } else if produced > skip_remaining {
                    // Overshot — some of the decompressed data is file data
                    let file_start = skip_remaining as usize;
                    let file_bytes = (produced - skip_remaining).min(self.target_size);
                    let file_bytes = file_bytes as usize;

                    self.output_len = file_bytes;
                    self.output_read = 0;
                    self.output_buf[..file_bytes]
                        .copy_from_slice(&temp_buf[file_start..file_start + file_bytes]);

                    let remaining = self.target_size - file_bytes as u64;
                    if remaining == 0 {
                        self.state = ReadState::Done;
                    } else {
                        self.state = ReadState::EmittingData {
                            data_remaining: remaining,
                        };
                    }
                    return EngineRequest::OutputReady;
                }
                // produced == 0 falls through

                if result.status == DecompressStatus::StreamEnd && had_input {
                    self.state = ReadState::Done;
                    return EngineRequest::Done;
                }

                if self.input_pos >= self.input_buf.len() {
                    if self.eof {
                        // Only stop if decompressor made no progress at all.
                        // It may have internally buffered output to drain.
                        if result.bytes_consumed == 0 && result.bytes_produced == 0 {
                            self.state = ReadState::Done;
                            return EngineRequest::Done;
                        }
                        // Keep trying - decompressor may have more buffered output
                    } else {
                        match &self.state {
                            ReadState::DecompressingToTarget { skip_remaining } => {
                                let s = *skip_remaining;
                                self.state = ReadState::NeedInput {
                                    skip_remaining: s,
                                };
                            }
                            ReadState::EmittingData { data_remaining } => {
                                let d = *data_remaining;
                                self.state = ReadState::NeedInputEmitting {
                                    data_remaining: d,
                                };
                            }
                            _ => {}
                        }
                    }
                    EngineRequest::NeedInput
                } else {
                    self.step()
                }
            }
            Err(e) => EngineRequest::Error(e),
        }
    }

    fn decompress_and_emit(&mut self, data_remaining: u64) -> EngineRequest {
        let input = &self.input_buf[self.input_pos..];

        let had_input = !input.is_empty();
        let max_output = (data_remaining as usize).min(self.output_buf.len());
        match self
            .decompressor
            .decompress(input, &mut self.output_buf[..max_output])
        {
            Ok(result) => {
                self.input_pos += result.bytes_consumed;
                self.uncompressed_pos += result.bytes_produced as u64;

                if result.bytes_produced > 0 {
                    self.output_len = result.bytes_produced;
                    self.output_read = 0;

                    let remaining = data_remaining - result.bytes_produced as u64;
                    if remaining == 0 {
                        self.state = ReadState::Done;
                    } else {
                        self.state = ReadState::EmittingData {
                            data_remaining: remaining,
                        };
                    }
                    return EngineRequest::OutputReady;
                }

                // No output produced
                if result.status == DecompressStatus::StreamEnd && had_input {
                    // Decompressor genuinely reached end of stream
                    self.state = ReadState::Done;
                    return EngineRequest::Done;
                }

                // Need more input
                if self.input_pos >= self.input_buf.len() {
                    if self.eof {
                        if result.bytes_consumed == 0 && result.bytes_produced == 0 {
                            self.state = ReadState::Done;
                            return EngineRequest::Done;
                        }
                        // Keep trying - decompressor may have more buffered output
                    } else {
                        self.state = ReadState::NeedInputEmitting { data_remaining };
                    }
                    EngineRequest::NeedInput
                } else {
                    self.step()
                }
            }
            Err(e) => EngineRequest::Error(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::CompressionFormat;

    /// Helper: drive indexing engine with in-memory data.
    fn index_from_bytes(data: &[u8], format: CompressionFormat) -> ArchiveIndex {
        let mut engine =
            IndexingEngine::new(format, None, DEFAULT_CHECKPOINT_INTERVAL, data.len() as u64)
                .unwrap();
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
