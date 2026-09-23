use crate::compress::codec::CodecSpec;
use crate::compress::detect;
use crate::engine::checkpoint_strategy::{
    default_interval_for_format, CheckpointStrategy, FixedInterval,
};
use crate::engine::request::EngineRequest;
use crate::error::{Error, Result};
use crate::stream::{StreamIndex, StreamIndexer, StreamProgress, StreamReader};
use crate::sync::reader::EntryReader;
use std::io::{Read, Seek, SeekFrom};

const BUF_SIZE: usize = 64 * 1024;

/// Random access into a bare compressed file: a `.gz`, `.xz`, `.zst` or
/// `.bz2` whose contents are the data itself, no container.
///
/// ```no_run
/// use iluvatar::sync::Stream;
/// use std::fs::File;
///
/// let mut stream = Stream::new(File::open("log.gz")?)?;
/// let tail = stream.read_range(stream.len().unwrap() - 4096, 4096)?;
/// # Ok::<(), iluvatar::Error>(())
/// ```
pub struct Stream<R> {
    reader: R,
    index: StreamIndex,
}

impl<R> Stream<R> {
    /// Wrap a reader with an index built earlier.
    pub fn from_parts(reader: R, index: StreamIndex) -> Self {
        Self { reader, index }
    }

    pub fn into_parts(self) -> (R, StreamIndex) {
        (self.reader, self.index)
    }

    pub fn index(&self) -> &StreamIndex {
        &self.index
    }

    /// Unpacked length, known once the whole stream was indexed.
    pub fn len(&self) -> Option<u64> {
        self.index.unpacked_len
    }

    /// True when the stream is known to hold no bytes.
    pub fn is_empty(&self) -> bool {
        self.index.unpacked_len == Some(0)
    }
}

impl<R: Read + Seek> Stream<R> {
    /// Detect the compression format from the file's magic and index it
    /// with the format's default checkpoint interval.
    pub fn new(reader: R) -> Result<Self> {
        let mut reader = reader;
        let format = detect_format(&mut reader)?;
        Self::with_codec_and_strategy(
            reader,
            format.into(),
            FixedInterval::new(default_interval_for_format(format)),
        )
    }

    /// Detect the format and index with a custom checkpoint strategy.
    pub fn with_strategy<S: CheckpointStrategy>(reader: R, strategy: S) -> Result<Self> {
        let mut reader = reader;
        let format = detect_format(&mut reader)?;
        Self::with_codec_and_strategy(reader, format.into(), strategy)
    }

    /// Index a stream whose codec the caller knows (raw LZMA, a filter
    /// chain, an encrypted stream), with progress reporting: return
    /// `false` from the callback to stop early and keep a partial index.
    pub fn with_codec_and_strategy<S: CheckpointStrategy>(
        reader: R,
        codec: CodecSpec,
        strategy: S,
    ) -> Result<Self> {
        Self::build_with_progress(reader, codec, strategy, |_| true)
    }

    /// [`with_codec_and_strategy`](Self::with_codec_and_strategy) with a
    /// progress callback; returning `false` stops indexing early.
    pub fn build_with_progress<S, F>(
        reader: R,
        codec: CodecSpec,
        strategy: S,
        mut on_progress: F,
    ) -> Result<Self>
    where
        S: CheckpointStrategy,
        F: FnMut(&StreamProgress) -> bool,
    {
        let mut reader = reader;
        let compressed_len = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(0))?;
        let mut indexer = StreamIndexer::new(codec, strategy, Some(compressed_len))?;
        let mut buf = vec![0u8; BUF_SIZE];
        loop {
            match indexer.step() {
                EngineRequest::NeedInput => {
                    let n = reader.read(&mut buf)?;
                    if n == 0 {
                        indexer.signal_eof();
                    } else {
                        indexer.provide_data(&buf[..n]);
                    }
                }
                EngineRequest::SeekAndRead { offset, len } => {
                    reader.seek(SeekFrom::Start(offset))?;
                    let n = reader.read(&mut buf[..len.min(BUF_SIZE)])?;
                    if n == 0 {
                        indexer.signal_eof();
                    } else {
                        indexer.provide_data(&buf[..n]);
                    }
                }
                EngineRequest::OutputReady => while indexer.read_output(&mut buf) > 0 {},
                EngineRequest::Done => break,
                EngineRequest::Error(e) => return Err(e),
            }
            if !on_progress(&indexer.progress()) {
                break;
            }
        }
        Ok(Self {
            reader,
            index: indexer.finish(),
        })
    }

    /// Read `len` unpacked bytes starting at `offset`; shorter at the end.
    ///
    /// Each call is independent: it restores the nearest checkpoint and
    /// decodes forward from there. For many consecutive ranges, keep one
    /// [`StreamReader`](crate::StreamReader) alive and move it with
    /// [`seek_forward`](crate::StreamReader::seek_forward).
    pub fn read_range(&mut self, offset: u64, len: u64) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.open(offset, len)?.read_to_end(&mut out)?;
        Ok(out)
    }

    /// Stream an unpacked range through [`Read`].
    ///
    /// Each call is independent: it restores the nearest checkpoint and
    /// decodes forward from there. For many consecutive ranges, keep one
    /// [`StreamReader`](crate::StreamReader) alive and move it with
    /// [`seek_forward`](crate::StreamReader::seek_forward).
    pub fn open(&mut self, offset: u64, len: u64) -> Result<EntryReader<'_, R>> {
        let reader = StreamReader::new(&self.index, offset, len)?;
        Ok(EntryReader::over(&mut self.reader, reader))
    }
}

fn detect_format<R: Read + Seek>(reader: &mut R) -> Result<crate::compress::CompressionFormat> {
    let mut header = [0u8; 512];
    let mut len = 0;
    while len < header.len() {
        let n = reader.read(&mut header[len..])?;
        if n == 0 {
            break;
        }
        len += n;
    }
    reader.seek(SeekFrom::Start(0))?;
    detect::detect_format(&header[..len]).ok_or(Error::UnsupportedFormat)
}
