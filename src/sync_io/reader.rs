use crate::compress::detect;
use crate::engine::progress::IndexProgress;
use crate::engine::request::EngineRequest;
use crate::engine::state_machine::{IndexingEngine, ReadEngine, DEFAULT_CHECKPOINT_INTERVAL};
use crate::error::{Result, SupertarError};
use crate::index::entry::IndexEntry;
use crate::index::store::ArchiveIndex;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Default read buffer size.
const BUF_SIZE: usize = 64 * 1024;

/// High-level synchronous API for reading compressed tar archives.
///
/// Wraps the sans-I/O engine, providing a simple interface that
/// uses `std::fs::File` for I/O.
pub struct SyncArchive {
    path: std::path::PathBuf,
    index: ArchiveIndex,
}

impl SyncArchive {
    /// Open a compressed tar archive and build its index.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let index = Self::build_index(path, DEFAULT_CHECKPOINT_INTERVAL)?;
        Ok(Self {
            path: path.to_path_buf(),
            index,
        })
    }

    /// Open a compressed tar archive with a specific checkpoint interval.
    pub fn open_with_interval(
        path: impl AsRef<Path>,
        checkpoint_interval: u64,
    ) -> Result<Self> {
        let path = path.as_ref();
        let index = Self::build_index(path, checkpoint_interval)?;
        Ok(Self {
            path: path.to_path_buf(),
            index,
        })
    }

    /// Open with a pre-built index.
    pub fn open_with_index(path: impl AsRef<Path>, index: ArchiveIndex) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            index,
        }
    }

    /// Build an index with progress reporting via a callback.
    ///
    /// The callback receives an `IndexProgress` after each engine step.
    /// Return `false` from the callback to cancel indexing early and
    /// receive a partial index.
    pub fn build_index_with_progress<F>(
        path: impl AsRef<Path>,
        checkpoint_interval: u64,
        mut on_progress: F,
    ) -> Result<ArchiveIndex>
    where
        F: FnMut(&IndexProgress) -> bool,
    {
        let path = path.as_ref();
        let mut file = File::open(path)?;
        let file_size = file.metadata()?.len();

        let mut header = [0u8; 512];
        let header_len = file.read(&mut header)?;
        let format =
            detect::detect_format(&header[..header_len]).ok_or(SupertarError::UnsupportedFormat)?;

        file.seek(SeekFrom::Start(0))?;

        let mut engine = IndexingEngine::new(format, None, checkpoint_interval, file_size)?;
        let mut buf = vec![0u8; BUF_SIZE];

        loop {
            match engine.step() {
                EngineRequest::NeedInput => {
                    let n = file.read(&mut buf)?;
                    if n == 0 {
                        engine.signal_eof();
                    } else {
                        engine.provide_data(&buf[..n]);
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

    /// Build an index by scanning the entire archive.
    pub fn build_index(path: impl AsRef<Path>, checkpoint_interval: u64) -> Result<ArchiveIndex> {
        let path = path.as_ref();
        let mut file = File::open(path)?;
        let file_size = file.metadata()?.len();

        // Detect compression format
        let mut header = [0u8; 512];
        let header_len = file.read(&mut header)?;
        let format = detect::detect_format(&header[..header_len])
            .ok_or(SupertarError::UnsupportedFormat)?;

        // Reset to beginning
        file.seek(SeekFrom::Start(0))?;

        let mut engine = IndexingEngine::new(format, None, checkpoint_interval, file_size)?;
        let mut buf = vec![0u8; BUF_SIZE];

        loop {
            match engine.step() {
                EngineRequest::NeedInput => {
                    let n = file.read(&mut buf)?;
                    if n == 0 {
                        engine.signal_eof();
                    } else {
                        engine.provide_data(&buf[..n]);
                    }
                }
                EngineRequest::Done => break,
                EngineRequest::Error(e) => return Err(e),
                _ => {}
            }
        }

        Ok(engine.finish())
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

    /// Read a file's contents from the archive.
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        let mut file = File::open(&self.path)?;
        let mut engine = ReadEngine::new(&self.index, path)?;
        let mut result = Vec::new();
        let mut buf = vec![0u8; BUF_SIZE];

        loop {
            match engine.step() {
                EngineRequest::NeedInput => {
                    let n = file.read(&mut buf)?;
                    if n == 0 {
                        engine.signal_eof();
                    } else {
                        engine.provide_data(&buf[..n]);
                    }
                }
                EngineRequest::SeekAndRead { offset, len } => {
                    file.seek(SeekFrom::Start(offset))?;
                    let read_len = len.min(buf.len());
                    let n = file.read(&mut buf[..read_len])?;
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
    pub fn read_file_range(&self, path: &str, offset: u64, len: u64) -> Result<Vec<u8>> {
        let mut file = File::open(&self.path)?;
        let mut engine = ReadEngine::new_range(&self.index, path, offset, len)?;
        let mut result = Vec::new();
        let mut buf = vec![0u8; BUF_SIZE];

        loop {
            match engine.step() {
                EngineRequest::NeedInput => {
                    let n = file.read(&mut buf)?;
                    if n == 0 {
                        engine.signal_eof();
                    } else {
                        engine.provide_data(&buf[..n]);
                    }
                }
                EngineRequest::SeekAndRead { offset, len } => {
                    file.seek(SeekFrom::Start(offset))?;
                    let read_len = len.min(buf.len());
                    let n = file.read(&mut buf[..read_len])?;
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

    /// Save the index to a file.
    pub fn save_index(&self, path: impl AsRef<Path>) -> Result<()> {
        let bytes = self.index.to_bytes()?;
        std::fs::write(path, bytes)?;
        Ok(())
    }

    /// Load a pre-built index from a file.
    pub fn load_index(path: impl AsRef<Path>) -> Result<ArchiveIndex> {
        let bytes = std::fs::read(path)?;
        ArchiveIndex::from_bytes(&bytes)
    }
}
