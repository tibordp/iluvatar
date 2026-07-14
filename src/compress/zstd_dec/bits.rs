//! Bit readers for zstd bitstreams.
//!
//! Zstd sequences and Huffman literals use a backward bitstream: bits are
//! read from the END of the compressed data toward the beginning. The reader
//! initializes by finding the leading 1-bit in the last byte, then reads bits
//! in that reversed order.

/// A forward bit reader (reads bits left-to-right from a byte slice).
/// Used for FSE NCount header decoding.
#[derive(Debug, Clone)]
pub(crate) struct ForwardBitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    bit_pos: u32, // 0..8 within current byte
}

impl<'a> ForwardBitReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_pos: 0,
            bit_pos: 0,
        }
    }

    /// Total bits consumed so far.
    pub fn bits_consumed(&self) -> usize {
        self.byte_pos * 8 + self.bit_pos as usize
    }

    /// Bytes consumed (rounded up).
    pub fn bytes_consumed(&self) -> usize {
        self.bits_consumed().div_ceil(8)
    }

    /// Read up to 25 bits (enough for FSE NCount reading).
    /// Reads from LSB to MSB within each byte.
    pub fn read_bits(&mut self, n: u32) -> Result<u32, &'static str> {
        if n == 0 {
            return Ok(0);
        }
        if n > 25 {
            return Err("too many bits requested");
        }
        // Build a u32 from current position
        let mut result: u32 = 0;
        let mut bits_read: u32 = 0;
        while bits_read < n {
            if self.byte_pos >= self.data.len() {
                return Err("read past end of bitstream");
            }
            let available = 8 - self.bit_pos;
            let to_read = (n - bits_read).min(available);
            let mask = (1u32 << to_read) - 1;
            let bits = ((self.data[self.byte_pos] >> self.bit_pos) as u32) & mask;
            result |= bits << bits_read;
            bits_read += to_read;
            self.bit_pos += to_read;
            if self.bit_pos >= 8 {
                self.bit_pos = 0;
                self.byte_pos += 1;
            }
        }
        Ok(result)
    }
}

/// Load up to 8 bytes little-endian starting at `byte_idx`, zero-padding
/// past the end of `data`.
#[inline(always)]
fn load_u64_le(data: &[u8], byte_idx: usize) -> u64 {
    if byte_idx + 8 <= data.len() {
        // Safe unaligned little-endian load.
        u64::from_le_bytes(data[byte_idx..byte_idx + 8].try_into().unwrap())
    } else {
        let mut buf = [0u8; 8];
        if byte_idx < data.len() {
            let n = data.len() - byte_idx;
            buf[..n].copy_from_slice(&data[byte_idx..]);
        }
        u64::from_le_bytes(buf)
    }
}

/// Extract `n` bits starting at absolute bit index `lo` from `data`
/// (bit 0 = LSB of byte 0). `n <= 56`. Bits past the end read as zero.
#[inline(always)]
pub(crate) fn extract_bits(data: &[u8], lo: usize, n: usize) -> usize {
    debug_assert!(n <= 56);
    if n == 0 {
        return 0;
    }
    let v = load_u64_le(data, lo >> 3);
    ((v >> (lo & 7)) as usize) & ((1usize << n) - 1)
}

/// Backward bit reader for zstd sequence and Huffman bitstreams.
///
/// The bitstream is read from the end. Initialization finds the leading 1-bit
/// in the last byte and starts reading from there toward the beginning.
///
/// Reads are implemented as unaligned 64-bit loads, so a read of up to
/// 56 bits costs a load + shift + mask instead of a per-bit loop.
#[derive(Debug, Clone)]
pub(crate) struct BackwardBitReader<'a> {
    data: &'a [u8],
    /// Total number of valid bits (after removing the init-marker).
    total_bits: usize,
    /// Current bit position: counts bits consumed from the MSB end.
    bit_pos: usize,
}

impl<'a> BackwardBitReader<'a> {
    /// Create a new backward bit reader from the given data.
    /// Finds the leading 1-bit in the last byte (the init marker).
    pub fn new(data: &'a [u8]) -> Result<Self, &'static str> {
        if data.is_empty() {
            return Err("empty bitstream");
        }
        let last_byte = data[data.len() - 1];
        if last_byte == 0 {
            return Err("last byte of bitstream is 0 (no init bit)");
        }
        // Find the highest set bit in the last byte
        let highest_bit = 7 - last_byte.leading_zeros() as usize;
        // Total bits available = (data.len()-1)*8 + highest_bit
        // The init 1-bit itself is not part of the data.
        let total_bits = (data.len() - 1) * 8 + highest_bit;

        Ok(Self {
            data,
            total_bits,
            bit_pos: 0,
        })
    }

    /// How many bits are still available to read.
    #[inline(always)]
    pub fn bits_remaining(&self) -> usize {
        self.total_bits.saturating_sub(self.bit_pos)
    }

    /// Whether reads have gone past the end of the stream (only possible via
    /// `read_bits_padded`).
    #[inline(always)]
    pub fn is_overflowed(&self) -> bool {
        self.bit_pos > self.total_bits
    }

    /// Peek `n` bits (MSB first from the end of data) without consuming.
    /// If fewer than `n` bits remain, the missing low bits read as zero.
    /// `n` must be <= 56.
    #[inline(always)]
    pub fn peek_bits_padded(&self, n: u32) -> usize {
        debug_assert!(n <= 56);
        if n == 0 {
            return 0;
        }
        let n = n as usize;
        let remaining = self.total_bits.saturating_sub(self.bit_pos);
        if remaining >= n {
            // Value occupies absolute bits [remaining - n, remaining).
            let lo = remaining - n;
            let v = load_u64_le(self.data, lo >> 3);
            ((v >> (lo & 7)) as usize) & ((1usize << n) - 1)
        } else {
            // Fewer than n real bits: real bits form the MSBs, zeros pad the rest.
            let v = (load_u64_le(self.data, 0) as usize) & ((1usize << remaining) - 1);
            v << (n - remaining)
        }
    }

    /// Read `n` bits from the bitstream (MSB first from the end of data).
    /// Returns an error if fewer than `n` bits remain. `n` must be <= 56.
    #[inline(always)]
    pub fn read_bits(&mut self, n: u32) -> Result<usize, &'static str> {
        if (n as usize) > self.bits_remaining() {
            return Err("not enough bits in backward bitstream");
        }
        let v = self.peek_bits_padded(n);
        self.bit_pos += n as usize;
        Ok(v)
    }

    /// Read `n` bits, zero-padding past the end of the stream. This matches
    /// the reference behavior where BIT_readBits continues reading from the
    /// bit container past the logical end; `is_overflowed` reports it.
    #[inline(always)]
    pub fn read_bits_padded(&mut self, n: u32) -> usize {
        let v = self.peek_bits_padded(n);
        self.bit_pos += n as usize;
        v
    }
}

/// Backward bit reader that keeps up to 56 upcoming bits in a u64 register,
/// refilling from memory only when the cache runs dry. Used for the sequence
/// bitstream where reads are strict (reading past the end is an error).
#[derive(Debug, Clone)]
pub(crate) struct SeqBitReader<'a> {
    data: &'a [u8],
    /// Bits not yet consumed (including the cached ones).
    rem: usize,
    /// MSB-aligned cache of the next `cbits` bits.
    cache: u64,
    cbits: usize,
}

impl<'a> SeqBitReader<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, &'static str> {
        let reader = BackwardBitReader::new(data)?;
        Ok(Self {
            data,
            rem: reader.bits_remaining(),
            cache: 0,
            cbits: 0,
        })
    }

    /// Read `n` bits MSB-first (n <= 56). Errors if fewer than `n` remain.
    #[inline(always)]
    pub fn read(&mut self, n: usize) -> Result<usize, ()> {
        if n == 0 {
            return Ok(0);
        }
        if self.cbits < n {
            if self.rem < n {
                return Err(());
            }
            // Refill: cache the next min(rem, 56) unconsumed bits. The
            // already-cached bits are re-read (idempotent).
            let avail = self.rem.min(56);
            let bits = extract_bits(self.data, self.rem - avail, avail);
            self.cache = (bits as u64) << (64 - avail);
            self.cbits = avail;
        }
        let v = (self.cache >> (64 - n)) as usize;
        self.cache <<= n;
        self.cbits -= n;
        self.rem -= n;
        Ok(v)
    }
}

/// Compute floor(log2(x)) for x > 0.
pub(crate) fn highest_bit(x: u32) -> u32 {
    debug_assert!(x > 0);
    31 - x.leading_zeros()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forward_bit_reader_basic() {
        // 0b10110100 = 0xB4
        let data = [0xB4];
        let mut reader = ForwardBitReader::new(&data);
        // Read bit by bit (LSB first): 0,0,1,0,1,1,0,1
        assert_eq!(reader.read_bits(1).unwrap(), 0);
        assert_eq!(reader.read_bits(1).unwrap(), 0);
        assert_eq!(reader.read_bits(1).unwrap(), 1);
        assert_eq!(reader.read_bits(1).unwrap(), 0);
        assert_eq!(reader.read_bits(1).unwrap(), 1);
        assert_eq!(reader.read_bits(1).unwrap(), 1);
        assert_eq!(reader.read_bits(1).unwrap(), 0);
        assert_eq!(reader.read_bits(1).unwrap(), 1);
    }

    #[test]
    fn test_forward_multi_byte() {
        let data = [0xFF, 0x01]; // bits: 11111111 10000000 (MSB view)
        let mut reader = ForwardBitReader::new(&data);
        assert_eq!(reader.read_bits(8).unwrap(), 0xFF);
        assert_eq!(reader.read_bits(1).unwrap(), 1);
        assert_eq!(reader.read_bits(7).unwrap(), 0);
    }

    #[test]
    fn test_forward_read_bits_multi() {
        let data = [0b00110101, 0b11001010];
        let mut reader = ForwardBitReader::new(&data);
        // Read 4 bits: should be bottom 4 of first byte = 0101 = 5
        assert_eq!(reader.read_bits(4).unwrap(), 0b0101);
        // Next 4 bits: top 4 of first byte = 0011 = 3
        assert_eq!(reader.read_bits(4).unwrap(), 0b0011);
    }

    #[test]
    fn test_backward_bit_reader_basic() {
        // Single byte 0b10000000 = 0x80
        // Init bit is bit 7, so total_bits = 7, all zero
        let data = [0x80];
        let reader = BackwardBitReader::new(&data).unwrap();
        assert_eq!(reader.bits_remaining(), 7);
    }

    #[test]
    fn test_backward_bit_reader_values() {
        // Data: [0x05, 0x80]
        // Last byte 0x80 -> highest bit = 7, total_bits = 1*8 + 7 = 15
        // Reading from end toward beginning
        let data = [0x05, 0x80];
        let mut reader = BackwardBitReader::new(&data).unwrap();
        assert_eq!(reader.bits_remaining(), 15);
        // The bits in order (MSB of last byte first, excluding init):
        // byte[1]=0x80=10000000, after init bit (bit7), remaining bits in byte1: bits 6..0 = 0000000
        // byte[0]=0x05=00000101
        // Reading MSB-first from end: 0,0,0,0,0,0,0 (byte1 bits 6..0), then 0,0,0,0,0,1,0,1 (byte0)
        let val = reader.read_bits(7).unwrap();
        assert_eq!(val, 0); // 7 zeros from byte 1
        let val = reader.read_bits(8).unwrap();
        assert_eq!(val, 5); // byte 0 = 0x05, read MSB first: 00000101
    }

    #[test]
    fn test_backward_bit_by_bit_equivalence() {
        // Compare wide reads against per-bit reads on a pseudo-random buffer.
        let data: Vec<u8> = (0..64u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .chain(std::iter::once(0x95))
            .collect();

        let mut wide = BackwardBitReader::new(&data).unwrap();
        let mut narrow = BackwardBitReader::new(&data).unwrap();

        for n in [1u32, 3, 7, 8, 13, 16, 25, 31, 40, 56, 5, 2] {
            if (n as usize) > wide.bits_remaining() {
                break;
            }
            let a = wide.read_bits(n).unwrap();
            let mut b = 0usize;
            for _ in 0..n {
                b = (b << 1) | narrow.read_bits(1).unwrap();
            }
            assert_eq!(a, b, "mismatch at width {n}");
        }
    }

    #[test]
    fn test_backward_padded_reads() {
        let data = [0x05, 0x80]; // 15 valid bits
        let mut reader = BackwardBitReader::new(&data).unwrap();
        reader.read_bits(7).unwrap();
        // 8 bits remain; ask for 12 padded: value = 0x05 << 4
        let v = reader.read_bits_padded(12);
        assert_eq!(v, 0x05 << 4);
        assert!(reader.is_overflowed());
    }

    #[test]
    fn test_highest_bit() {
        assert_eq!(highest_bit(1), 0);
        assert_eq!(highest_bit(2), 1);
        assert_eq!(highest_bit(3), 1);
        assert_eq!(highest_bit(4), 2);
        assert_eq!(highest_bit(64), 6);
        assert_eq!(highest_bit(255), 7);
    }
}
