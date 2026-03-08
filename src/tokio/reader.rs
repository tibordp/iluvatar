use crate::compress::detect;
use crate::engine::progress::IndexProgress;
use crate::engine::request::EngineRequest;
use crate::engine::state_machine::{IndexingEngine, ReadEngine, DEFAULT_CHECKPOINT_INTERVAL};
use crate::error::{Result, SupertarError};
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
/// Tokio's [`AsyncRead`] and [`AsyncSeek`] traits.
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

// ─── Forward-only indexing (AsyncRead, no AsyncSeek) ───

impl<R: AsyncRead + Unpin> Archive<R> {
    /// Index a compressed archive from a forward-only async reader.
    ///
    /// `file_size` is used for progress reporting; pass 0 if unknown.
    pub async fn from_reader(reader: R, file_size: u64) -> Result<Self> {
        Self::from_reader_with_interval(reader, file_size, DEFAULT_CHECKPOINT_INTERVAL).await
    }

    /// Index a compressed archive from a forward-only async reader with a
    /// specific checkpoint interval.
    ///
    /// `file_size` is used for progress reporting; pass 0 if unknown.
    pub async fn from_reader_with_interval(
        mut reader: R,
        file_size: u64,
        checkpoint_interval: u64,
    ) -> Result<Self> {
        let index = Self::build_index_with_progress(
            &mut reader,
            file_size,
            checkpoint_interval,
            |_| true,
        )
        .await?;
        Ok(Self { reader, index })
    }

    /// Build an index with progress reporting via a callback.
    ///
    /// `file_size` is used for progress reporting; pass 0 if unknown.
    /// The callback receives an `IndexProgress` after each engine step.
    /// Return `false` from the callback to cancel indexing early and
    /// receive a partial index.
    pub async fn build_index_with_progress<F>(
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
            let n = reader.read(&mut header[header_len..]).await?;
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
}

// ─── Seekable reader (AsyncRead + AsyncSeek) ───

impl<R: AsyncRead + AsyncSeek + Unpin> Archive<R> {
    /// Index a compressed archive and build an `Archive`.
    ///
    /// Detects the compression format and archive size automatically
    /// by seeking.
    pub async fn new(reader: R) -> Result<Self> {
        Self::new_with_interval(reader, DEFAULT_CHECKPOINT_INTERVAL).await
    }

    /// Index a compressed archive with a specific checkpoint interval.
    ///
    /// Detects the compression format and archive size automatically
    /// by seeking.
    pub async fn new_with_interval(mut reader: R, checkpoint_interval: u64) -> Result<Self> {
        let file_size = reader.seek(SeekFrom::End(0)).await?;
        reader.seek(SeekFrom::Start(0)).await?;
        let mut archive =
            Self::from_reader_with_interval(reader, file_size, checkpoint_interval).await?;
        archive.reader.seek(SeekFrom::Start(0)).await?;
        Ok(archive)
    }

    /// Read a file's contents from the archive.
    pub async fn read_file(&mut self, path: &str) -> Result<Vec<u8>> {
        self.reader.seek(SeekFrom::Start(0)).await?;
        let mut engine = ReadEngine::new(&self.index, path)?;
        let mut result = Vec::new();
        let mut buf = vec![0u8; BUF_SIZE];

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
    pub async fn read_file_range(
        &mut self,
        path: &str,
        offset: u64,
        len: u64,
    ) -> Result<Vec<u8>> {
        self.reader.seek(SeekFrom::Start(0)).await?;
        let mut engine = ReadEngine::new_range(&self.index, path, offset, len)?;
        let mut result = Vec::new();
        let mut buf = vec![0u8; BUF_SIZE];

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
    /// Returns an [`EntryReader`] that implements [`AsyncRead`], allowing
    /// you to stream a file's contents without buffering it all in memory.
    ///
    /// The returned reader mutably borrows this archive, so only one
    /// file can be open at a time.
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
/// used with `read_to_end`, `tokio::io::copy`, etc.
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
