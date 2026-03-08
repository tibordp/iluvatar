use crate::compress::detect;
use crate::engine::progress::IndexProgress;
use crate::engine::request::EngineRequest;
use crate::engine::state_machine::{IndexingEngine, ReadEngine, DEFAULT_CHECKPOINT_INTERVAL};
use crate::error::{Result, SupertarError};
use crate::index::entry::IndexEntry;
use crate::index::store::ArchiveIndex;
use std::io::{Read, Seek, SeekFrom};

/// Default read buffer size.
const BUF_SIZE: usize = 64 * 1024;

/// High-level synchronous API for reading compressed tar/cpio archives.
///
/// Wraps the sans-I/O engine, providing a simple interface for any
/// reader that implements [`Read`] (for indexing) or [`Read`] + [`Seek`]
/// (for reading file contents).
pub struct Archive<R> {
    reader: R,
    index: ArchiveIndex,
}

// ─── Methods that don't touch the reader ───

impl<R> Archive<R> {
    /// Create from a reader with a pre-built index.
    pub fn from_parts(reader: R, index: ArchiveIndex) -> Self {
        Self { reader, index }
    }

    /// Consume the archive, returning the reader and index.
    pub fn into_parts(self) -> (R, ArchiveIndex) {
        (self.reader, self.index)
    }

    /// Get a reference to the index.
    pub fn index(&self) -> &ArchiveIndex {
        &self.index
    }

    /// List all entries in the archive.
    pub fn list(&self) -> Vec<&IndexEntry> {
        self.index.list(None)
    }

    /// List entries under a directory prefix.
    pub fn list_dir(&self, prefix: &str) -> Vec<&IndexEntry> {
        self.index.list(Some(prefix))
    }

    /// Get metadata for a specific file.
    pub fn entry(&self, path: &str) -> Option<&IndexEntry> {
        self.index.get(path)
    }
}

// ─── Forward-only indexing (Read, no Seek) ───

impl<R: Read> Archive<R> {
    /// Index a compressed archive from a forward-only reader.
    ///
    /// `file_size` is used for progress reporting; pass 0 if unknown.
    pub fn from_reader(reader: R, file_size: u64) -> Result<Self> {
        Self::from_reader_with_interval(reader, file_size, DEFAULT_CHECKPOINT_INTERVAL)
    }

    /// Index a compressed archive from a forward-only reader with a
    /// specific checkpoint interval.
    ///
    /// `file_size` is used for progress reporting; pass 0 if unknown.
    pub fn from_reader_with_interval(
        mut reader: R,
        file_size: u64,
        checkpoint_interval: u64,
    ) -> Result<Self> {
        let index = Self::build_index_with_progress(
            &mut reader,
            file_size,
            checkpoint_interval,
            |_| true,
        )?;
        Ok(Self { reader, index })
    }

    /// Build an index with progress reporting via a callback.
    ///
    /// `file_size` is used for progress reporting; pass 0 if unknown.
    /// The callback receives an `IndexProgress` after each engine step.
    /// Return `false` from the callback to cancel indexing early and
    /// receive a partial index.
    pub fn build_index_with_progress<F>(
        reader: &mut R,
        file_size: u64,
        checkpoint_interval: u64,
        mut on_progress: F,
    ) -> Result<ArchiveIndex>
    where
        F: FnMut(&IndexProgress) -> bool,
    {
        // Read header for compression format detection.
        // Loop because read() may return partial results.
        let mut header = [0u8; 512];
        let mut header_len = 0;
        while header_len < header.len() {
            let n = reader.read(&mut header[header_len..])?;
            if n == 0 {
                break;
            }
            header_len += n;
        }
        let format = detect::detect_format(&header[..header_len])
            .ok_or(SupertarError::UnsupportedFormat)?;

        let mut engine = IndexingEngine::new(format, None, checkpoint_interval, file_size)?;
        let mut buf = vec![0u8; BUF_SIZE];

        // Feed the header bytes we already read as the first input
        let mut header_fed = false;

        loop {
            match engine.step() {
                EngineRequest::NeedInput => {
                    if !header_fed {
                        engine.provide_data(&header[..header_len]);
                        header_fed = true;
                    } else {
                        let n = reader.read(&mut buf)?;
                        if n == 0 {
                            engine.signal_eof();
                        } else {
                            engine.provide_data(&buf[..n]);
                        }
                    }
                }
                EngineRequest::Done => break,
                EngineRequest::Error(e) => return Err(e),
                _ => {}
            }

            let progress = engine.progress();
            if !on_progress(&progress) {
                return Ok(engine.cancel());
            }
        }

        Ok(engine.finish())
    }
}

// ─── Seekable reader (Read + Seek) ───

impl<R: Read + Seek> Archive<R> {
    /// Index a compressed archive and build a `Archive`.
    ///
    /// Detects the compression format and archive size automatically
    /// by seeking.
    pub fn new(reader: R) -> Result<Self> {
        Self::new_with_interval(reader, DEFAULT_CHECKPOINT_INTERVAL)
    }

    /// Index a compressed archive with a specific checkpoint interval.
    ///
    /// Detects the compression format and archive size automatically
    /// by seeking.
    pub fn new_with_interval(mut reader: R, checkpoint_interval: u64) -> Result<Self> {
        let file_size = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(0))?;
        let mut archive = Self::from_reader_with_interval(reader, file_size, checkpoint_interval)?;
        archive.reader.seek(SeekFrom::Start(0))?;
        Ok(archive)
    }

    /// Read a file's contents from the archive.
    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>> {
        self.reader.seek(SeekFrom::Start(0))?;
        let mut engine = ReadEngine::new(&self.index, path)?;
        let mut result = Vec::new();
        let mut buf = vec![0u8; BUF_SIZE];

        loop {
            match engine.step() {
                EngineRequest::NeedInput => {
                    let n = self.reader.read(&mut buf)?;
                    if n == 0 {
                        engine.signal_eof();
                    } else {
                        engine.provide_data(&buf[..n]);
                    }
                }
                EngineRequest::SeekAndRead { offset, len } => {
                    self.reader.seek(SeekFrom::Start(offset))?;
                    let read_len = len.min(buf.len());
                    let n = self.reader.read(&mut buf[..read_len])?;
                    if n == 0 {
                        engine.signal_eof();
                    } else {
                        engine.provide_data(&buf[..n]);
                    }
                }
                EngineRequest::OutputReady => {
                    let mut out_buf = vec![0u8; BUF_SIZE];
                    loop {
                        let n = engine.read_output(&mut out_buf);
                        if n == 0 {
                            break;
                        }
                        result.extend_from_slice(&out_buf[..n]);
                    }
                }
                EngineRequest::Done => break,
                EngineRequest::Error(e) => return Err(e),
            }
        }

        Ok(result)
    }

    /// Read a byte range from a file in the archive.
    ///
    /// Reads `len` bytes starting at byte `offset` within the file.
    /// Seeks to the best checkpoint for that position, so reading
    /// from the middle of a large file is efficient.
    pub fn read_file_range(&mut self, path: &str, offset: u64, len: u64) -> Result<Vec<u8>> {
        self.reader.seek(SeekFrom::Start(0))?;
        let mut engine = ReadEngine::new_range(&self.index, path, offset, len)?;
        let mut result = Vec::new();
        let mut buf = vec![0u8; BUF_SIZE];

        loop {
            match engine.step() {
                EngineRequest::NeedInput => {
                    let n = self.reader.read(&mut buf)?;
                    if n == 0 {
                        engine.signal_eof();
                    } else {
                        engine.provide_data(&buf[..n]);
                    }
                }
                EngineRequest::SeekAndRead { offset, len } => {
                    self.reader.seek(SeekFrom::Start(offset))?;
                    let read_len = len.min(buf.len());
                    let n = self.reader.read(&mut buf[..read_len])?;
                    if n == 0 {
                        engine.signal_eof();
                    } else {
                        engine.provide_data(&buf[..n]);
                    }
                }
                EngineRequest::OutputReady => {
                    let mut out_buf = vec![0u8; BUF_SIZE];
                    loop {
                        let n = engine.read_output(&mut out_buf);
                        if n == 0 {
                            break;
                        }
                        result.extend_from_slice(&out_buf[..n]);
                    }
                }
                EngineRequest::Done => break,
                EngineRequest::Error(e) => return Err(e),
            }
        }

        Ok(result)
    }

    /// Open a file in the archive for streaming reads.
    ///
    /// Returns an [`EntryReader`] that implements [`Read`], allowing
    /// you to stream a file's contents without buffering it all in memory.
    ///
    /// The returned reader mutably borrows this archive, so only one
    /// file can be open at a time.
    pub fn open(&mut self, path: &str) -> Result<EntryReader<'_, R>> {
        self.reader.seek(SeekFrom::Start(0))?;
        let engine = ReadEngine::new(&self.index, path)?;
        Ok(EntryReader {
            reader: &mut self.reader,
            engine,
            buf: vec![0u8; BUF_SIZE],
            done: false,
        })
    }
}

/// Streaming reader for a single file within an archive.
///
/// Created by [`Archive::open`](Archive::open). Implements [`Read`] so it can be
/// used with `read_to_end`, `BufReader`, `io::copy`, etc.
pub struct EntryReader<'a, R> {
    reader: &'a mut R,
    engine: ReadEngine,
    buf: Vec<u8>,
    done: bool,
}

impl<R: Read + Seek> std::io::Read for EntryReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.done {
            return Ok(0);
        }

        // Drain any buffered output from a previous call
        let n = self.engine.read_output(buf);
        if n > 0 {
            return Ok(n);
        }

        // Drive the engine until we have output or are done
        loop {
            match self.engine.step() {
                EngineRequest::NeedInput => {
                    let n = self.reader.read(&mut self.buf)?;
                    if n == 0 {
                        self.engine.signal_eof();
                    } else {
                        self.engine.provide_data(&self.buf[..n]);
                    }
                }
                EngineRequest::SeekAndRead { offset, len } => {
                    self.reader.seek(SeekFrom::Start(offset))?;
                    let read_len = len.min(self.buf.len());
                    let n = self.reader.read(&mut self.buf[..read_len])?;
                    if n == 0 {
                        self.engine.signal_eof();
                    } else {
                        self.engine.provide_data(&self.buf[..n]);
                    }
                }
                EngineRequest::OutputReady => {
                    let n = self.engine.read_output(buf);
                    if n > 0 {
                        return Ok(n);
                    }
                }
                EngineRequest::Done => {
                    self.done = true;
                    return Ok(0);
                }
                EngineRequest::Error(e) => {
                    self.done = true;
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, e));
                }
            }
        }
    }
}
