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
use ::tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, ReadBuf};
use std::io::SeekFrom;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Default read buffer size.
const BUF_SIZE: usize = 64 * 1024;

/// High-level asynchronous API for reading compressed tar/cpio archives.
///
/// This is the async equivalent of [`crate::sync::Archive`], using
/// Tokio's [`AsyncRead`] and [`AsyncSeek`] traits. See the
/// [module docs](crate::tokio) for usage examples.
pub struct Archive<R> {
    reader: R,
    index: ArchiveIndex,
}

// ─── Methods that don't touch the reader ───

impl<R> Archive<R> {
    /// Create from a reader with a pre-built index.
    ///
    /// See [`crate::sync::Archive::from_parts`] for details.
    pub fn from_parts(reader: R, index: ArchiveIndex) -> Self {
        Self { reader, index }
    }

    /// Consume the archive, returning the reader and index.
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
    pub fn list_dir(&self, prefix: &str) -> Vec<&IndexEntry> {
        self.index.list(Some(prefix))
    }

    /// Get metadata for a specific file without reading its contents.
    pub fn entry(&self, path: &str) -> Option<&IndexEntry> {
        self.index.get(path)
    }
}

// ─── Forward-only indexing (AsyncRead, no AsyncSeek) ───

impl<R: AsyncRead + Unpin> Archive<R> {
    /// Index a compressed archive from a forward-only async reader.
    ///
    /// Uses the default checkpoint strategy for the detected compression
    /// format. `file_size` is used for progress reporting; pass 0 if unknown.
    pub async fn from_reader(reader: R, file_size: u64) -> Result<Self> {
        let mut reader = reader;
        let index = Self::build_index_with_progress(&mut reader, file_size, |_| true).await?;
        Ok(Self { reader, index })
    }

    /// Index a compressed archive from a forward-only async reader with a
    /// custom checkpoint strategy.
    ///
    /// `file_size` is used for progress reporting; pass 0 if unknown.
    pub async fn from_reader_with_strategy<S: CheckpointStrategy>(
        reader: R,
        file_size: u64,
        strategy: S,
    ) -> Result<Self> {
        let mut reader = reader;
        let index =
            Self::build_index_with_strategy(&mut reader, file_size, strategy, |_| true).await?;
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
    pub async fn build_index_with_progress<F>(
        reader: &mut R,
        file_size: u64,
        on_progress: F,
    ) -> Result<ArchiveIndex>
    where
        F: FnMut(&IndexProgress) -> bool,
    {
        let (format, header, header_len) = detect_format_from_reader(reader).await?;
        let strategy = FixedInterval::new(default_interval_for_format(format));
        drive_indexing(
            reader,
            file_size,
            format,
            &header[..header_len],
            strategy,
            on_progress,
        )
        .await
    }

    /// Build an index with a custom checkpoint strategy and progress reporting.
    ///
    /// `file_size` is used for progress reporting; pass 0 if unknown.
    ///
    /// The callback receives an `IndexProgress` after each engine step.
    /// Return `false` from the callback to cancel indexing early and
    /// receive a partial index.
    pub async fn build_index_with_strategy<S, F>(
        reader: &mut R,
        file_size: u64,
        strategy: S,
        on_progress: F,
    ) -> Result<ArchiveIndex>
    where
        S: CheckpointStrategy,
        F: FnMut(&IndexProgress) -> bool,
    {
        let (format, header, header_len) = detect_format_from_reader(reader).await?;
        drive_indexing(
            reader,
            file_size,
            format,
            &header[..header_len],
            strategy,
            on_progress,
        )
        .await
    }
}

// ─── Seekable reader (AsyncRead + AsyncSeek) ───

impl<R: AsyncRead + AsyncSeek + Unpin> Archive<R> {
    /// Index a compressed archive and build an `Archive`.
    ///
    /// Detects the compression format and archive size automatically
    /// by seeking. Uses the default checkpoint strategy for the detected
    /// compression format.
    ///
    /// ```no_run
    /// # async fn example() -> iluvatar::Result<()> {
    /// use iluvatar::tokio::Archive;
    ///
    /// let file = tokio::fs::File::open("data.tar.gz").await?;
    /// let mut archive = Archive::new(file).await?;
    /// let data = archive.read_file("README.md").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new(reader: R) -> Result<Self> {
        let mut reader = reader;
        let file_size = reader.seek(SeekFrom::End(0)).await?;
        reader.seek(SeekFrom::Start(0)).await?;
        let index = Self::build_index_with_progress(&mut reader, file_size, |_| true).await?;
        reader.seek(SeekFrom::Start(0)).await?;
        Ok(Self { reader, index })
    }

    /// Index a compressed archive with a custom checkpoint strategy.
    ///
    /// Detects the compression format and archive size automatically
    /// by seeking.
    pub async fn with_strategy<S: CheckpointStrategy>(reader: R, strategy: S) -> Result<Self> {
        let mut reader = reader;
        let file_size = reader.seek(SeekFrom::End(0)).await?;
        reader.seek(SeekFrom::Start(0)).await?;
        let index =
            Self::build_index_with_strategy(&mut reader, file_size, strategy, |_| true).await?;
        reader.seek(SeekFrom::Start(0)).await?;
        Ok(Self { reader, index })
    }

    /// Read a file's entire contents from the archive into memory.
    ///
    /// For large files, consider [`read_file_range()`](Self::read_file_range)
    /// or [`open()`](Self::open) to avoid loading everything at once.
    pub async fn read_file(&mut self, path: &str) -> Result<Vec<u8>> {
        self.reader.seek(SeekFrom::Start(0)).await?;
        let mut engine = ReadEngine::new(&self.index, path)?;
        let mut result = Vec::new();
        let mut buf = vec![0u8; BUF_SIZE];
        let mut out_buf = vec![0u8; BUF_SIZE];

        loop {
            match engine.step() {
                EngineRequest::NeedInput => {
                    let n = self.reader.read(&mut buf).await?;
                    if n == 0 {
                        engine.signal_eof();
                    } else {
                        engine.provide_data(&buf[..n]);
                    }
                }
                EngineRequest::SeekAndRead { offset, len } => {
                    self.reader.seek(SeekFrom::Start(offset)).await?;
                    let read_len = len.min(buf.len());
                    let n = self.reader.read(&mut buf[..read_len]).await?;
                    if n == 0 {
                        engine.signal_eof();
                    } else {
                        engine.provide_data(&buf[..n]);
                    }
                }
                EngineRequest::OutputReady => loop {
                    let n = engine.read_output(&mut out_buf);
                    if n == 0 {
                        break;
                    }
                    result.extend_from_slice(&out_buf[..n]);
                },
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
    pub async fn read_file_range(&mut self, path: &str, offset: u64, len: u64) -> Result<Vec<u8>> {
        self.reader.seek(SeekFrom::Start(0)).await?;
        let mut engine = ReadEngine::new_range(&self.index, path, offset, len)?;
        let mut result = Vec::new();
        let mut buf = vec![0u8; BUF_SIZE];
        let mut out_buf = vec![0u8; BUF_SIZE];

        loop {
            match engine.step() {
                EngineRequest::NeedInput => {
                    let n = self.reader.read(&mut buf).await?;
                    if n == 0 {
                        engine.signal_eof();
                    } else {
                        engine.provide_data(&buf[..n]);
                    }
                }
                EngineRequest::SeekAndRead { offset, len } => {
                    self.reader.seek(SeekFrom::Start(offset)).await?;
                    let read_len = len.min(buf.len());
                    let n = self.reader.read(&mut buf[..read_len]).await?;
                    if n == 0 {
                        engine.signal_eof();
                    } else {
                        engine.provide_data(&buf[..n]);
                    }
                }
                EngineRequest::OutputReady => loop {
                    let n = engine.read_output(&mut out_buf);
                    if n == 0 {
                        break;
                    }
                    result.extend_from_slice(&out_buf[..n]);
                },
                EngineRequest::Done => break,
                EngineRequest::Error(e) => return Err(e),
            }
        }

        Ok(result)
    }

    /// Open a file in the archive for streaming reads.
    ///
    /// Returns an [`EntryReader`] that implements [`AsyncRead`], allowing
    /// you to stream a file's contents without buffering it all in memory.
    ///
    /// The returned reader mutably borrows this archive, so only one
    /// file can be open at a time.
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use iluvatar::tokio::Archive;
    ///
    /// let file = tokio::fs::File::open("data.tar.gz").await?;
    /// let mut archive = Archive::new(file).await?;
    ///
    /// let mut reader = archive.open("large-file.bin").await?;
    /// tokio::io::copy(&mut reader, &mut tokio::io::stdout()).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn open(&mut self, path: &str) -> Result<EntryReader<'_, R>> {
        self.reader.seek(SeekFrom::Start(0)).await?;
        let engine = ReadEngine::new(&self.index, path)?;
        Ok(EntryReader {
            reader: &mut self.reader,
            engine,
            io_buf: vec![0u8; BUF_SIZE],
            state: PollState::DriveEngine,
        })
    }
}

// ─── Private helpers ───

/// Read the header from an async reader and detect the compression format.
async fn detect_format_from_reader<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<(CompressionFormat, [u8; 512], usize)> {
    let mut header = [0u8; 512];
    let mut header_len = 0;
    while header_len < header.len() {
        let n = reader.read(&mut header[header_len..]).await?;
        if n == 0 {
            break;
        }
        header_len += n;
    }
    let format = detect::detect_format(&header[..header_len]).ok_or(Error::UnsupportedFormat)?;
    Ok((format, header, header_len))
}

/// Drive the indexing engine to completion with the given strategy.
async fn drive_indexing<
    R: AsyncRead + Unpin,
    S: CheckpointStrategy,
    F: FnMut(&IndexProgress) -> bool,
>(
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
                    let n = reader.read(&mut buf).await?;
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

/// Internal state for the poll-based [`EntryReader`].
#[derive(Clone, Copy)]
enum PollState {
    /// Drive the engine to determine the next action.
    DriveEngine,
    /// Initiate a seek to `offset`, then read `read_len` bytes.
    StartSeek { offset: u64, read_len: usize },
    /// Wait for a pending seek to complete, then read `read_len` bytes.
    WaitSeek { read_len: usize },
    /// Read up to `read_len` bytes from the underlying reader.
    PendingRead { read_len: usize },
    /// All data has been produced.
    Done,
}

/// Streaming async reader for a single file within an archive.
///
/// Created by [`Archive::open`]. Implements [`AsyncRead`] so it can be
/// used with `tokio::io::copy`, `read_to_end`, etc.
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use iluvatar::tokio::Archive;
///
/// let file = tokio::fs::File::open("data.tar.gz").await?;
/// let mut archive = Archive::new(file).await?;
/// let mut reader = archive.open("file.txt").await?;
/// let mut out = tokio::io::stdout();
/// tokio::io::copy(&mut reader, &mut out).await?;
/// # Ok(())
/// # }
/// ```
pub struct EntryReader<'a, R> {
    reader: &'a mut R,
    engine: ReadEngine,
    io_buf: Vec<u8>,
    state: PollState,
}

impl<R: AsyncRead + AsyncSeek + Unpin> AsyncRead for EntryReader<'_, R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        loop {
            let state = this.state;
            match state {
                PollState::Done => return Poll::Ready(Ok(())),

                PollState::DriveEngine => {
                    // Try to drain buffered output from a previous step
                    let unfilled = buf.initialize_unfilled();
                    let n = this.engine.read_output(unfilled);
                    if n > 0 {
                        buf.advance(n);
                        return Poll::Ready(Ok(()));
                    }

                    match this.engine.step() {
                        EngineRequest::NeedInput => {
                            this.state = PollState::PendingRead {
                                read_len: this.io_buf.len(),
                            };
                        }
                        EngineRequest::SeekAndRead { offset, len } => {
                            let read_len = len.min(this.io_buf.len());
                            this.state = PollState::StartSeek { offset, read_len };
                        }
                        EngineRequest::OutputReady => {
                            let unfilled = buf.initialize_unfilled();
                            let n = this.engine.read_output(unfilled);
                            if n > 0 {
                                buf.advance(n);
                                return Poll::Ready(Ok(()));
                            }
                        }
                        EngineRequest::Done => {
                            this.state = PollState::Done;
                            return Poll::Ready(Ok(()));
                        }
                        EngineRequest::Error(e) => {
                            this.state = PollState::Done;
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                e,
                            )));
                        }
                    }
                }

                PollState::StartSeek { offset, read_len } => {
                    Pin::new(&mut *this.reader).start_seek(SeekFrom::Start(offset))?;
                    this.state = PollState::WaitSeek { read_len };
                }

                PollState::WaitSeek { read_len } => {
                    match Pin::new(&mut *this.reader).poll_complete(cx)? {
                        Poll::Ready(_) => {
                            this.state = PollState::PendingRead { read_len };
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }

                PollState::PendingRead { read_len } => {
                    let mut read_buf = ReadBuf::new(&mut this.io_buf[..read_len]);
                    match Pin::new(&mut *this.reader).poll_read(cx, &mut read_buf)? {
                        Poll::Ready(()) => {
                            let n = read_buf.filled().len();
                            if n == 0 {
                                this.engine.signal_eof();
                            } else {
                                this.engine.provide_data(&this.io_buf[..n]);
                            }
                            this.state = PollState::DriveEngine;
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }
}
