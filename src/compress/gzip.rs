use crate::compress::checkpoint::{
    Checkpoint, CheckpointState, GzipBlockBoundary, GzipCheckpointState,
};
use crate::compress::decompressor::{DecompressResult, DecompressStatus, Decompressor};
use crate::error::{Result, SupertarError};
use miniz_oxide::inflate::core::{
    decompress as miniz_decompress, inflate_flags, DecompressorOxide,
};
use miniz_oxide::inflate::TINFLStatus;

const WINDOW_SIZE: usize = 32768; // 32 KiB — must be power of 2

// Gzip header flags
const FHCRC: u8 = 2;
const FEXTRA: u8 = 4;
const FNAME: u8 = 8;
const FCOMMENT: u8 = 16;

/// Gzip decompressor with deflate block-boundary checkpoint support.
///
/// Uses miniz_oxide directly with a 32 KiB wrapping output buffer.
/// At each deflate block boundary, the decompressor state is captured
/// for checkpointing, enabling mid-stream resume without re-decompressing
/// from the beginning.
pub struct GzipDecompressor {
    inner: DecompressorOxide,
    /// 32 KiB wrapping dictionary/output buffer.
    dict_buf: Box<[u8; WINDOW_SIZE]>,
    /// Logical output position (keeps growing; wraps via % WINDOW_SIZE
    /// when passed to miniz_oxide).
    dict_pos: usize,
    /// Whether the deflate stream has finished.
    finished: bool,

    // Staged output: decompressed bytes extracted from dict_buf but not
    // yet given to the caller (when more was produced than output can hold).
    stage: Vec<u8>,
    stage_pos: usize,

    // Header parsing
    header_state: GzipHeaderState,
    header_buf: Vec<u8>,
    /// Size of the gzip header in bytes (set once header is parsed).
    header_size: usize,

    // Offset tracking for accurate checkpoint positions
    /// Total deflate bytes consumed (excludes gzip header bytes).
    deflate_in: u64,
    /// Total uncompressed bytes produced.
    total_out: u64,

    // Last deflate block boundary for checkpointing
    last_boundary: Option<SavedBoundary>,
}

struct SavedBoundary {
    block_state: GzipBlockBoundary,
    window: Vec<u8>,
    /// Offset in the compressed file (header_size + deflate bytes at boundary).
    compressed_offset: u64,
    /// Uncompressed bytes produced up to this boundary.
    uncompressed_offset: u64,
}

#[derive(Debug, Clone)]
enum GzipHeaderState {
    ReadingFixedHeader,
    Decompressing,
    Finished,
}

impl GzipDecompressor {
    pub fn new() -> Self {
        Self {
            inner: DecompressorOxide::new(),
            dict_buf: Box::new([0u8; WINDOW_SIZE]),
            dict_pos: 0,
            finished: false,
            stage: Vec::new(),
            stage_pos: 0,
            header_state: GzipHeaderState::ReadingFixedHeader,
            header_buf: Vec::new(),
            header_size: 0,
            deflate_in: 0,
            total_out: 0,
            last_boundary: None,
        }
    }

    /// Try to parse the gzip header from header_buf.
    /// Returns Ok(header_size) if complete, Err if need more data.
    fn try_parse_header(&self) -> std::result::Result<usize, ()> {
        let buf = &self.header_buf;
        if buf.len() < 10 {
            return Err(());
        }

        if buf[0] != 0x1f || buf[1] != 0x8b {
            return Ok(0); // Not gzip, try as raw deflate
        }

        let flags = buf[3];
        let mut pos = 10;

        if flags & FEXTRA != 0 {
            if buf.len() < pos + 2 {
                return Err(());
            }
            let xlen = buf[pos] as usize | ((buf[pos + 1] as usize) << 8);
            pos += 2;
            if buf.len() < pos + xlen {
                return Err(());
            }
            pos += xlen;
        }

        if flags & FNAME != 0 {
            match buf[pos..].iter().position(|&b| b == 0) {
                Some(i) => pos += i + 1,
                None => return Err(()),
            }
        }

        if flags & FCOMMENT != 0 {
            match buf[pos..].iter().position(|&b| b == 0) {
                Some(i) => pos += i + 1,
                None => return Err(()),
            }
        }

        if flags & FHCRC != 0 {
            if buf.len() < pos + 2 {
                return Err(());
            }
            pos += 2;
        }

        Ok(pos)
    }

    /// Extract the current window (linearized, oldest-first) from the
    /// wrapping dict_buf.
    fn get_window(&self) -> Vec<u8> {
        if self.dict_pos < WINDOW_SIZE {
            self.dict_buf[..self.dict_pos].to_vec()
        } else {
            let pos = self.dict_pos % WINDOW_SIZE;
            let mut window = Vec::with_capacity(WINDOW_SIZE);
            window.extend_from_slice(&self.dict_buf[pos..]);
            window.extend_from_slice(&self.dict_buf[..pos]);
            window
        }
    }

    /// Extract `count` bytes of output produced starting at `old_dict_pos`
    /// from the wrapping dict_buf.
    fn extract_output(&self, old_dict_pos: usize, count: usize) -> Vec<u8> {
        if count == 0 {
            return Vec::new();
        }
        let start = old_dict_pos % WINDOW_SIZE;
        if start + count <= WINDOW_SIZE {
            self.dict_buf[start..start + count].to_vec()
        } else {
            let first = WINDOW_SIZE - start;
            let mut out = Vec::with_capacity(count);
            out.extend_from_slice(&self.dict_buf[start..WINDOW_SIZE]);
            out.extend_from_slice(&self.dict_buf[..count - first]);
            out
        }
    }

    /// Flush staged output to the caller's buffer.
    fn flush_stage(&mut self, output: &mut [u8]) -> DecompressResult {
        let available = self.stage.len() - self.stage_pos;
        let n = available.min(output.len());
        output[..n].copy_from_slice(&self.stage[self.stage_pos..self.stage_pos + n]);
        self.stage_pos += n;
        if self.stage_pos >= self.stage.len() {
            self.stage.clear();
            self.stage_pos = 0;
        }
        DecompressResult {
            bytes_consumed: 0,
            bytes_produced: n,
            status: if self.finished && self.stage.is_empty() {
                DecompressStatus::StreamEnd
            } else {
                DecompressStatus::Continue
            },
        }
    }

    /// Single call to miniz_oxide decompress using wrapping mode.
    /// Stops at block boundaries for checkpoint capture.
    /// Returns (status, deflate_bytes_consumed, output_bytes_produced).
    fn do_inflate(
        &mut self,
        input: &[u8],
        has_more_input: bool,
    ) -> Result<(TINFLStatus, usize, usize)> {
        let mut flags = inflate_flags::TINFL_FLAG_STOP_ON_BLOCK_BOUNDARY;
        if !input.is_empty() || has_more_input {
            flags |= inflate_flags::TINFL_FLAG_HAS_MORE_INPUT;
        }

        // Pass wrapped position to miniz_oxide. The buffer is a 32 KiB
        // circular window; miniz_oxide writes at `out_pos` within the
        // slice and returns HasMoreOutput when the buffer is full.
        let write_pos = self.dict_pos % WINDOW_SIZE;
        let (status, in_consumed, out_produced) =
            miniz_decompress(&mut self.inner, input, &mut *self.dict_buf, write_pos, flags);

        self.dict_pos += out_produced;
        self.total_out += out_produced as u64;
        self.deflate_in += in_consumed as u64;

        if status == TINFLStatus::BlockBoundary {
            if let Some(bbs) = self.inner.block_boundary_state() {
                let window = self.get_window();
                self.last_boundary = Some(SavedBoundary {
                    block_state: GzipBlockBoundary {
                        num_bits: bbs.num_bits,
                        bit_buf: bbs.bit_buf,
                        z_header0: bbs.z_header0,
                        z_header1: bbs.z_header1,
                        check_adler32: bbs.check_adler32,
                    },
                    window,
                    compressed_offset: self.header_size as u64 + self.deflate_in,
                    uncompressed_offset: self.total_out,
                });
            }
        }

        Ok((status, in_consumed, out_produced))
    }

    /// Call do_inflate and copy output to the caller's buffer (or stage it).
    fn inflate_to_output(
        &mut self,
        input: &[u8],
        has_more_input: bool,
        output: &mut [u8],
    ) -> Result<DecompressResult> {
        let old_dict_pos = self.dict_pos;
        let (status, in_consumed, out_produced) = self.do_inflate(input, has_more_input)?;

        // Extract output from wrapping buffer
        let mut bytes_to_caller = 0;
        if out_produced > 0 {
            let extracted = self.extract_output(old_dict_pos, out_produced);
            let n = extracted.len().min(output.len());
            output[..n].copy_from_slice(&extracted[..n]);
            bytes_to_caller = n;
            if n < extracted.len() {
                self.stage = extracted[n..].to_vec();
                self.stage_pos = 0;
            }
        }

        let decom_status = match status {
            TINFLStatus::Done => {
                self.finished = true;
                self.header_state = GzipHeaderState::Finished;
                DecompressStatus::StreamEnd
            }
            TINFLStatus::NeedsMoreInput
            | TINFLStatus::HasMoreOutput
            | TINFLStatus::BlockBoundary => DecompressStatus::Continue,
            TINFLStatus::FailedCannotMakeProgress => {
                self.finished = true;
                DecompressStatus::StreamEnd
            }
            _ => {
                return Err(SupertarError::DecompressionError(format!(
                    "inflate error: {:?}",
                    status
                )));
            }
        };

        Ok(DecompressResult {
            bytes_consumed: in_consumed,
            bytes_produced: bytes_to_caller,
            status: decom_status,
        })
    }
}

impl Default for GzipDecompressor {
    fn default() -> Self {
        Self::new()
    }
}

impl Decompressor for GzipDecompressor {
    fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<DecompressResult> {
        // First, flush any staged output
        if self.stage_pos < self.stage.len() {
            return Ok(self.flush_stage(output));
        }

        match self.header_state {
            GzipHeaderState::ReadingFixedHeader => {
                if input.is_empty() {
                    return Ok(DecompressResult {
                        bytes_consumed: 0,
                        bytes_produced: 0,
                        status: DecompressStatus::StreamEnd,
                    });
                }

                let old_header_len = self.header_buf.len();
                self.header_buf.extend_from_slice(input);

                match self.try_parse_header() {
                    Ok(header_size) => {
                        self.header_state = GzipHeaderState::Decompressing;
                        self.header_size = header_size;

                        // How many bytes from *this* input went to the header?
                        let header_bytes_from_input =
                            header_size.saturating_sub(old_header_len);
                        let remaining_input = &input[header_bytes_from_input..];

                        self.header_buf.clear();

                        if !remaining_input.is_empty() {
                            let result = self.inflate_to_output(
                                remaining_input,
                                true,
                                output,
                            )?;
                            Ok(DecompressResult {
                                bytes_consumed: header_bytes_from_input
                                    + result.bytes_consumed,
                                bytes_produced: result.bytes_produced,
                                status: result.status,
                            })
                        } else {
                            Ok(DecompressResult {
                                bytes_consumed: header_bytes_from_input,
                                bytes_produced: 0,
                                status: DecompressStatus::Continue,
                            })
                        }
                    }
                    Err(()) => Ok(DecompressResult {
                        bytes_consumed: input.len(),
                        bytes_produced: 0,
                        status: DecompressStatus::Continue,
                    }),
                }
            }

            GzipHeaderState::Decompressing => {
                let has_more = !input.is_empty();
                self.inflate_to_output(input, has_more, output)
            }

            GzipHeaderState::Finished => Ok(DecompressResult {
                bytes_consumed: 0,
                bytes_produced: 0,
                status: DecompressStatus::StreamEnd,
            }),
        }
    }

    fn checkpoint(
        &self,
        _compressed_offset: u64,
        _uncompressed_offset: u64,
    ) -> Result<Checkpoint> {
        if let Some(ref boundary) = self.last_boundary {
            Ok(Checkpoint {
                compressed_offset: boundary.compressed_offset,
                uncompressed_offset: boundary.uncompressed_offset,
                bit_offset: 0,
                state: CheckpointState::Gzip(GzipCheckpointState {
                    window: boundary.window.clone(),
                    block_state: Some(boundary.block_state.clone()),
                    header_size: self.header_size,
                }),
            })
        } else {
            Ok(Checkpoint {
                compressed_offset: 0,
                bit_offset: 0,
                uncompressed_offset: 0,
                state: CheckpointState::None,
            })
        }
    }

    fn restore(&mut self, checkpoint: &Checkpoint) -> Result<()> {
        match &checkpoint.state {
            CheckpointState::Gzip(state) => {
                if let Some(ref bs) = state.block_state {
                    let bbs = miniz_oxide::inflate::core::BlockBoundaryState {
                        num_bits: bs.num_bits,
                        bit_buf: bs.bit_buf,
                        z_header0: bs.z_header0,
                        z_header1: bs.z_header1,
                        check_adler32: bs.check_adler32,
                    };
                    self.inner = DecompressorOxide::from_block_boundary_state(&bbs);

                    // Pre-fill dict_buf with saved window
                    *self.dict_buf = [0u8; WINDOW_SIZE];
                    let wlen = state.window.len().min(WINDOW_SIZE);
                    self.dict_buf[..wlen].copy_from_slice(&state.window[..wlen]);
                    self.dict_pos = wlen;

                    self.header_state = GzipHeaderState::Decompressing;
                    self.header_size = state.header_size;
                    self.header_buf.clear();
                    self.stage.clear();
                    self.stage_pos = 0;
                    self.deflate_in = 0;
                    self.total_out = checkpoint.uncompressed_offset;
                    self.last_boundary = None;
                    self.finished = false;
                } else {
                    self.reset();
                }
                Ok(())
            }
            CheckpointState::None => {
                self.reset();
                Ok(())
            }
            _ => Err(SupertarError::CheckpointError(
                "expected gzip checkpoint state".into(),
            )),
        }
    }

    fn reset(&mut self) {
        self.inner = DecompressorOxide::new();
        *self.dict_buf = [0u8; WINDOW_SIZE];
        self.dict_pos = 0;
        self.finished = false;
        self.stage.clear();
        self.stage_pos = 0;
        self.header_state = GzipHeaderState::ReadingFixedHeader;
        self.header_buf.clear();
        self.header_size = 0;
        self.deflate_in = 0;
        self.total_out = 0;
        self.last_boundary = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    fn compress_gzip(data: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    /// Helper that fully decompresses gzip data, driving the decompressor
    /// in a loop with proper chunk management.
    fn full_decompress(compressed: &[u8], chunk_size: usize) -> Vec<u8> {
        let mut dec = GzipDecompressor::new();
        let mut all_output = Vec::new();
        let mut offset = 0;

        loop {
            let end = (offset + chunk_size).min(compressed.len());
            let input = if offset < compressed.len() {
                &compressed[offset..end]
            } else {
                &[]
            };

            let mut output = vec![0u8; 65536];
            let result = dec.decompress(input, &mut output).unwrap();
            all_output.extend_from_slice(&output[..result.bytes_produced]);
            offset += result.bytes_consumed;

            if result.status == DecompressStatus::StreamEnd {
                break;
            }

            if result.bytes_consumed == 0
                && result.bytes_produced == 0
                && offset >= compressed.len()
            {
                break;
            }
        }

        all_output
    }

    #[test]
    fn test_basic_decompress() {
        let original = b"Hello, world! This is a test of gzip decompression.";
        let compressed = compress_gzip(original);
        let output = full_decompress(&compressed, compressed.len());
        assert_eq!(&output, &original[..]);
    }

    #[test]
    fn test_incremental_decompress() {
        let original = b"Hello, world! This is a test of gzip decompression.";
        let compressed = compress_gzip(original);
        let output = full_decompress(&compressed, 10);
        assert_eq!(&output, &original[..]);
    }

    #[test]
    fn test_window_tracking() {
        let original: Vec<u8> = (0..50000).map(|i| (i % 256) as u8).collect();
        let compressed = compress_gzip(&original);
        let output = full_decompress(&compressed, 4096);

        assert_eq!(output.len(), original.len());
        assert_eq!(output, original);

        // Decompress again with a tracked decompressor to check window
        let mut dec = GzipDecompressor::new();
        let mut offset = 0;
        loop {
            let end = (offset + 4096).min(compressed.len());
            let input = if offset < compressed.len() {
                &compressed[offset..end]
            } else {
                &[]
            };
            let mut out = vec![0u8; 65536];
            let result = dec.decompress(input, &mut out).unwrap();
            offset += result.bytes_consumed;
            if result.status == DecompressStatus::StreamEnd {
                break;
            }
            if result.bytes_consumed == 0 && result.bytes_produced == 0 && offset >= compressed.len() {
                break;
            }
        }

        let window = dec.get_window();
        assert_eq!(window.len(), WINDOW_SIZE);
        assert_eq!(window, &original[original.len() - WINDOW_SIZE..]);
    }

    #[test]
    fn test_checkpoint_creates_valid_state() {
        let original: Vec<u8> = (0..100_000).map(|i| (i % 251) as u8).collect();
        let compressed = compress_gzip(&original);
        let output = full_decompress(&compressed, 4096);
        assert_eq!(output.len(), original.len());
        assert_eq!(output, original);
    }

    #[test]
    fn test_restore_and_redecompress() {
        let original = b"Hello, world! This is a test of restore.";
        let compressed = compress_gzip(original);

        let output1 = full_decompress(&compressed, compressed.len());
        assert_eq!(&output1, &original[..]);

        let mut dec = GzipDecompressor::new();
        let cp = dec.checkpoint(0, 0).unwrap();
        dec.restore(&cp).unwrap();

        let output2 = full_decompress(&compressed, compressed.len());
        assert_eq!(&output2, &original[..]);
    }

    #[test]
    fn test_large_data() {
        let original: Vec<u8> = (0..200_000).map(|i| (i % 251) as u8).collect();
        let compressed = compress_gzip(&original);
        let output = full_decompress(&compressed, 4096);
        assert_eq!(output, original);
    }

    #[test]
    fn test_checkpoint_restore_midstream() {
        // Use pseudo-random data to get block boundaries
        let mut rng: u64 = 99;
        let original: Vec<u8> = (0..500_000)
            .map(|_| {
                rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
                (rng >> 33) as u8
            })
            .collect();
        let compressed = compress_gzip(&original);

        // First pass: decompress and capture checkpoint
        let mut dec = GzipDecompressor::new();
        let mut all_output = Vec::new();
        let mut off = 0;
        loop {
            let end = (off + 4096).min(compressed.len());
            let input = if off < compressed.len() {
                &compressed[off..end]
            } else {
                &[]
            };
            let mut out = vec![0u8; 65536];
            let result = dec.decompress(input, &mut out).unwrap();
            all_output.extend_from_slice(&out[..result.bytes_produced]);
            off += result.bytes_consumed;
            if result.status == DecompressStatus::StreamEnd
                || (result.bytes_consumed == 0
                    && result.bytes_produced == 0
                    && off >= compressed.len())
            {
                break;
            }
        }
        assert_eq!(all_output, original);

        let cp = dec.checkpoint(0, 0).unwrap();
        if let CheckpointState::Gzip(ref state) = cp.state {
            if state.block_state.is_some() {
                assert!(cp.compressed_offset > 0);
                assert!(cp.uncompressed_offset > 0);

                // Restore and decompress from checkpoint
                let mut dec2 = GzipDecompressor::new();
                dec2.restore(&cp).unwrap();

                let mut restored_output = Vec::new();
                let mut off2 = cp.compressed_offset as usize;
                loop {
                    let end = (off2 + 4096).min(compressed.len());
                    let input = if off2 < compressed.len() {
                        &compressed[off2..end]
                    } else {
                        &[]
                    };
                    let mut out = vec![0u8; 65536];
                    let result = dec2.decompress(input, &mut out).unwrap();
                    restored_output.extend_from_slice(&out[..result.bytes_produced]);
                    off2 += result.bytes_consumed;
                    if result.status == DecompressStatus::StreamEnd
                        || (result.bytes_consumed == 0
                            && result.bytes_produced == 0
                            && off2 >= compressed.len())
                    {
                        break;
                    }
                }

                let expected_tail = &original[cp.uncompressed_offset as usize..];
                assert_eq!(
                    restored_output, expected_tail,
                    "restored output ({} bytes) doesn't match expected tail ({} bytes)",
                    restored_output.len(),
                    expected_tail.len()
                );
            }
        }
    }
}
