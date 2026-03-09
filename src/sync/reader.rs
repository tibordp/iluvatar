use crate::compress::detect;
use crate::compress::CompressionFormat;
use crate::engine::checkpoint_strategy::{
    default_interval_for_format, CheckpointStrategy, FixedInterval,
};
use crate::engine::progress::IndexProgress;
use crate::engine::request::EngineRequest;
use crate::engine::state_machine::{IndexingEngine, ReadEngine};
use crate::error::{Error, Result};
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
///
/// # Example
///
/// ```no_run
/// use iluvatar::sync::Archive;
/// use std::fs::File;
///
/// let file = File::open("data.tar.gz")?;
/// let mut archive = Archive::new(file)?;
///
/// // List files
/// for entry in archive.list() {
///     println!("{} ({} bytes)", entry.path, entry.size);
/// }
///
/// // Read a specific file
/// let data = archive.read_file("path/to/file.txt")?;
/// # Ok::<(), iluvatar::Error>(())
/// ```
pub struct Archive<R> {
    reader: R,
    index: ArchiveIndex,
}

// ─── Methods that don't touch the reader ───

impl<R> Archive<R> {
    /// Create from a reader with a pre-built index.
    ///
    /// Use this when you have a previously serialized index (via
    /// [`ArchiveIndex::from_bytes`]) and want to skip the indexing pass.
    ///
    /// ```no_run
    /// # fn example() -> iluvatar::Result<()> {
    /// use iluvatar::sync::Archive;
    /// use iluvatar::ArchiveIndex;
    /// use std::fs::File;
    ///
    /// let index = ArchiveIndex::from_bytes(&std::fs::read("data.idx")?)?;
    /// let file = File::open("data.tar.gz")?;
    /// let mut archive = Archive::from_parts(file, index);
    /// let data = archive.read_file("README.md")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_parts(reader: R, index: ArchiveIndex) -> Self {
        Self { reader, index }
    }

    /// Consume the archive, returning the reader and index.
    ///
    /// Useful for saving the index for later reuse.
    ///
    /// ```no_run
    /// # fn example() -> iluvatar::Result<()> {
    /// use iluvatar::sync::Archive;
    /// use std::fs::File;
    ///
    /// let archive = Archive::new(File::open("data.tar.gz")?)?;
    /// let (_, index) = archive.into_parts();
    /// std::fs::write("data.idx", index.to_bytes()?)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn into_parts(self) -> (R, ArchiveIndex) {
        (self.reader, self.index)
    }

    /// Get a reference to the underlying index.
    pub fn index(&self) -> &ArchiveIndex {
        &self.index
    }

    /// List all entries in the archive.
    pub fn list(&self) -> Vec<&IndexEntry> {
        self.index.list(None)
    }

    /// List entries under a directory prefix.
    ///
    /// ```no_run
    /// # fn example(archive: &iluvatar::sync::Archive<std::fs::File>) {
    /// for entry in archive.list_dir("src") {
    ///     println!("{}", entry.path); // e.g. "src/main.rs"
    /// }
    /// # }
    /// ```
    pub fn list_dir(&self, prefix: &str) -> Vec<&IndexEntry> {
        self.index.list(Some(prefix))
    }

    /// Get metadata for a specific file without reading its contents.
    pub fn entry(&self, path: &str) -> Option<&IndexEntry> {
        self.index.get(path)
    }
}

// ─── Forward-only indexing (Read, no Seek) ───

impl<R: Read> Archive<R> {
    /// Index a compressed archive from a forward-only reader.
    ///
    /// Uses the default checkpoint strategy for the detected compression
    /// format. `file_size` is used for progress reporting; pass 0 if unknown.
    ///
    /// The resulting archive can only list files and access the index;
    /// reading file contents requires a reader that also implements [`Seek`].
    ///
    /// ```no_run
    /// # fn example() -> iluvatar::Result<()> {
    /// use iluvatar::sync::Archive;
    ///
    /// let stdin = std::io::stdin().lock();
    /// let archive = Archive::from_reader(stdin, 0)?;
    /// for entry in archive.list() {
    ///     println!("{}", entry.path);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_reader(reader: R, file_size: u64) -> Result<Self> {
        let mut reader = reader;
        let index = Self::build_index_with_progress(&mut reader, file_size, |_| true)?;
        Ok(Self { reader, index })
    }

    /// Index a compressed archive from a forward-only reader with a
    /// custom checkpoint strategy.
    ///
    /// `file_size` is used for progress reporting; pass 0 if unknown.
    ///
    /// ```no_run
    /// # fn example() -> iluvatar::Result<()> {
    /// use iluvatar::sync::Archive;
    /// use iluvatar::FixedInterval;
    ///
    /// let stdin = std::io::stdin().lock();
    /// let strategy = FixedInterval::new(8 * 1024 * 1024);
    /// let archive = Archive::from_reader_with_strategy(stdin, 0, strategy)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_reader_with_strategy<S: CheckpointStrategy>(
        reader: R,
        file_size: u64,
        strategy: S,
    ) -> Result<Self> {
        let mut reader = reader;
        let index = Self::build_index_with_strategy(&mut reader, file_size, strategy, |_| true)?;
        Ok(Self { reader, index })
    }

    /// Build an index with progress reporting via a callback.
    ///
    /// Uses the default checkpoint strategy for the detected compression
    /// format. `file_size` is used for progress reporting; pass 0 if unknown.
    ///
    /// The callback receives an `IndexProgress` after each engine step.
    /// Return `false` from the callback to cancel indexing early and
    /// receive a partial index.
    pub fn build_index_with_progress<F>(
        reader: &mut R,
        file_size: u64,
        on_progress: F,
    ) -> Result<ArchiveIndex>
    where
        F: FnMut(&IndexProgress) -> bool,
    {
        let (format, header, header_len) = detect_format_from_reader(reader)?;
        let strategy = FixedInterval::new(default_interval_for_format(format));
        drive_indexing(
            reader,
            file_size,
            format,
            &header[..header_len],
            strategy,
            on_progress,
        )
    }

    /// Build an index with a custom checkpoint strategy and progress reporting.
    ///
    /// `file_size` is used for progress reporting; pass 0 if unknown.
    ///
    /// The callback receives an `IndexProgress` after each engine step.
    /// Return `false` from the callback to cancel indexing early and
    /// receive a partial index.
    pub fn build_index_with_strategy<S, F>(
        reader: &mut R,
        file_size: u64,
        strategy: S,
        on_progress: F,
    ) -> Result<ArchiveIndex>
    where
        S: CheckpointStrategy,
        F: FnMut(&IndexProgress) -> bool,
    {
        let (format, header, header_len) = detect_format_from_reader(reader)?;
        drive_indexing(
            reader,
            file_size,
            format,
            &header[..header_len],
            strategy,
            on_progress,
        )
    }
}

// ─── Seekable reader (Read + Seek) ───

impl<R: Read + Seek> Archive<R> {
    /// Index a compressed archive and build an `Archive`.
    ///
    /// Detects the compression format and archive size automatically
    /// by seeking. Uses the default checkpoint strategy for the detected
    /// compression format.
    ///
    /// This is the easiest way to get started — it handles format
    /// detection, indexing, and setup in one call.
    ///
    /// ```no_run
    /// # fn example() -> iluvatar::Result<()> {
    /// use iluvatar::sync::Archive;
    /// use std::fs::File;
    ///
    /// let mut archive = Archive::new(File::open("data.tar.gz")?)?;
    /// let data = archive.read_file("README.md")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(reader: R) -> Result<Self> {
        let mut reader = reader;
        let file_size = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(0))?;
        let index = Self::build_index_with_progress(&mut reader, file_size, |_| true)?;
        reader.seek(SeekFrom::Start(0))?;
        Ok(Self { reader, index })
    }

    /// Index a compressed archive with a custom checkpoint strategy.
    ///
    /// Detects the compression format and archive size automatically
    /// by seeking.
    ///
    /// ```no_run
    /// # fn example() -> iluvatar::Result<()> {
    /// use iluvatar::sync::Archive;
    /// use iluvatar::Budget;
    /// use std::fs::File;
    ///
    /// let strategy = Budget::new(5 * 1024 * 1024); // 5 MiB index budget
    /// let mut archive = Archive::with_strategy(File::open("data.tar.zst")?, strategy)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_strategy<S: CheckpointStrategy>(reader: R, strategy: S) -> Result<Self> {
        let mut reader = reader;
        let file_size = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(0))?;
        let index = Self::build_index_with_strategy(&mut reader, file_size, strategy, |_| true)?;
        reader.seek(SeekFrom::Start(0))?;
        Ok(Self { reader, index })
    }

    /// Read a file's entire contents from the archive into memory.
    ///
    /// For large files, consider [`read_file_range()`](Self::read_file_range)
    /// or [`open()`](Self::open) to avoid loading everything at once.
    ///
    /// ```no_run
    /// # fn example(archive: &mut iluvatar::sync::Archive<std::fs::File>) -> iluvatar::Result<()> {
    /// let data = archive.read_file("README.md")?;
    /// println!("{} bytes", data.len());
    /// # Ok(())
    /// # }
    /// ```
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
    ///
    /// ```no_run
    /// # fn example(archive: &mut iluvatar::sync::Archive<std::fs::File>) -> iluvatar::Result<()> {
    /// // Read just the first 512 bytes (e.g. a file header)
    /// let header = archive.read_file_range("large-file.bin", 0, 512)?;
    ///
    /// // Read 1 KiB from the middle of a 10 GB file — only decompresses
    /// // from the nearest checkpoint, not from the beginning
    /// let chunk = archive.read_file_range("huge.dat", 5_000_000_000, 1024)?;
    /// # Ok(())
    /// # }
    /// ```
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
    ///
    /// ```no_run
    /// # fn example(archive: &mut iluvatar::sync::Archive<std::fs::File>) -> Result<(), Box<dyn std::error::Error>> {
    /// use std::io::Read;
    ///
    /// let mut reader = archive.open("large-file.bin")?;
    /// let mut buf = [0u8; 8192];
    /// let mut total = 0;
    /// loop {
    ///     let n = reader.read(&mut buf)?;
    ///     if n == 0 { break; }
    ///     total += n;
    /// }
    /// println!("read {total} bytes");
    /// # Ok(())
    /// # }
    /// ```
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

// ─── Private helpers ───

/// Read the header from a reader and detect the compression format.
fn detect_format_from_reader<R: Read>(
    reader: &mut R,
) -> Result<(CompressionFormat, [u8; 512], usize)> {
    let mut header = [0u8; 512];
    let mut header_len = 0;
    while header_len < header.len() {
        let n = reader.read(&mut header[header_len..])?;
        if n == 0 {
            break;
        }
        header_len += n;
    }
    let format = detect::detect_format(&header[..header_len]).ok_or(Error::UnsupportedFormat)?;
    Ok((format, header, header_len))
}

/// Drive the indexing engine to completion with the given strategy.
fn drive_indexing<R: Read, S: CheckpointStrategy, F: FnMut(&IndexProgress) -> bool>(
    reader: &mut R,
    file_size: u64,
    format: CompressionFormat,
    header: &[u8],
    strategy: S,
    mut on_progress: F,
) -> Result<ArchiveIndex> {
    let mut engine = IndexingEngine::with_strategy(format, None, strategy, file_size)?;
    let mut buf = vec![0u8; BUF_SIZE];
    let mut header_fed = false;

    loop {
        match engine.step() {
            EngineRequest::NeedInput => {
                if !header_fed {
                    engine.provide_data(header);
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

// ─── EntryReader ───

/// Streaming reader for a single file within an archive.
///
/// Created by [`Archive::open`]. Implements [`Read`] so it can be
/// used with `read_to_end`, `BufReader`, `io::copy`, etc.
///
/// ```no_run
/// # fn example(archive: &mut iluvatar::sync::Archive<std::fs::File>) -> Result<(), Box<dyn std::error::Error>> {
/// use std::io;
///
/// let mut reader = archive.open("file.txt")?;
/// io::copy(&mut reader, &mut io::stdout())?;
/// # Ok(())
/// # }
/// ```
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
