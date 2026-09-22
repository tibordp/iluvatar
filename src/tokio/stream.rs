use crate::compress::codec::CodecSpec;
use crate::compress::detect;
use crate::engine::checkpoint_strategy::{
    default_interval_for_format, CheckpointStrategy, FixedInterval,
};
use crate::engine::request::EngineRequest;
use crate::error::{Error, Result};
use crate::stream::{StreamIndex, StreamIndexer, StreamProgress, StreamReader};
use crate::tokio::reader::EntryReader;
use ::tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt};
use std::io::SeekFrom;

const BUF_SIZE: usize = 64 * 1024;

/// Async counterpart of [`crate::sync::Stream`]: random access into a bare
/// compressed file.
pub struct Stream<R> {
    reader: R,
    index: StreamIndex,
}

impl<R> Stream<R> {
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

impl<R: AsyncRead + AsyncSeek + Unpin> Stream<R> {
    /// Detect the compression format from the file's magic and index it
    /// with the format's default checkpoint interval.
    pub async fn new(reader: R) -> Result<Self> {
        let mut reader = reader;
        let format = detect_format(&mut reader).await?;
        Self::with_codec_and_strategy(
            reader,
            format.into(),
            FixedInterval::new(default_interval_for_format(format)),
        )
        .await
    }

    /// Detect the format and index with a custom checkpoint strategy.
    pub async fn with_strategy<S: CheckpointStrategy>(reader: R, strategy: S) -> Result<Self> {
        let mut reader = reader;
        let format = detect_format(&mut reader).await?;
        Self::with_codec_and_strategy(reader, format.into(), strategy).await
    }

    /// Index a stream whose codec the caller knows.
    pub async fn with_codec_and_strategy<S: CheckpointStrategy>(
        reader: R,
        codec: CodecSpec,
        strategy: S,
    ) -> Result<Self> {
        Self::build_with_progress(reader, codec, strategy, |_| true).await
    }

    /// [`with_codec_and_strategy`](Self::with_codec_and_strategy) with a
    /// progress callback; returning `false` stops indexing early.
    pub async fn build_with_progress<S, F>(
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
        let compressed_len = reader.seek(SeekFrom::End(0)).await?;
        reader.seek(SeekFrom::Start(0)).await?;
        let mut indexer = StreamIndexer::new(codec, strategy, Some(compressed_len))?;
        let mut buf = vec![0u8; BUF_SIZE];
        loop {
            match indexer.step() {
                EngineRequest::NeedInput => {
                    let n = reader.read(&mut buf).await?;
                    if n == 0 {
                        indexer.signal_eof();
                    } else {
                        indexer.provide_data(&buf[..n]);
                    }
                }
                EngineRequest::SeekAndRead { offset, len } => {
                    reader.seek(SeekFrom::Start(offset)).await?;
                    let n = reader.read(&mut buf[..len.min(BUF_SIZE)]).await?;
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
    pub async fn read_range(&mut self, offset: u64, len: u64) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.open(offset, len)?.read_to_end(&mut out).await?;
        Ok(out)
    }

    /// Stream an unpacked range through [`AsyncRead`].
    pub fn open(&mut self, offset: u64, len: u64) -> Result<EntryReader<'_, R>> {
        let reader = StreamReader::new(&self.index, offset, len)?;
        Ok(EntryReader::over(&mut self.reader, reader))
    }
}

async fn detect_format<R: AsyncRead + AsyncSeek + Unpin>(
    reader: &mut R,
) -> Result<crate::compress::CompressionFormat> {
    let mut header = [0u8; 512];
    let mut len = 0;
    while len < header.len() {
        let n = reader.read(&mut header[len..]).await?;
        if n == 0 {
            break;
        }
        len += n;
    }
    reader.seek(SeekFrom::Start(0)).await?;
    detect::detect_format(&header[..len]).ok_or(Error::UnsupportedFormat)
}
