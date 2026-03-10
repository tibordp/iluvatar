//! Bit reader for zstd backward bitstreams.
//!
//! Zstd sequences use a backward bitstream: bits are read from the END of
//! the compressed data toward the beginning. The reader initializes by
//! finding the leading 1-bit in the last byte, then reads bits in that
//! reversed order.

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
        let total_bit = self.byte_pos * 8 + self.bit_pos as usize;
        if total_bit + n as usize > self.data.len() * 8 {
            return Err("read past end of bitstream");
        }
        // Load up to 4 bytes into a u32 from current byte position
        let mut buf = [0u8; 4];
        let bytes_avail = self.data.len() - self.byte_pos;
        let bytes_to_copy = bytes_avail.min(4);
        buf[..bytes_to_copy].copy_from_slice(&self.data[self.byte_pos..self.byte_pos + bytes_to_copy]);
        let val = u32::from_le_bytes(buf);
        let result = (val >> self.bit_pos) & ((1u32 << n) - 1);
        let new_bit = self.bit_pos + n;
        self.byte_pos += (new_bit / 8) as usize;
        self.bit_pos = new_bit % 8;
        Ok(result)
    }
}

/// Backward bit reader for zstd sequence bitstreams.
///
/// The bitstream is read from the end. Initialization finds the leading 1-bit
/// in the last byte and starts reading from there toward the beginning.
#[derive(Debug, Clone)]
pub(crate) struct BackwardBitReader<'a> {
    /// The bitstream data (borrowed).
    data: &'a [u8],
    /// Current bit position: counts bits from the MSB end of the last byte.
    /// Starts after the init-marker bit.
    bit_pos: usize,
    /// Total number of valid bits (after removing the init-marker).
    total_bits: usize,
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
            bit_pos: 0,
            total_bits,
        })
    }

    /// How many bits are still available to read.
    #[inline]
    pub fn bits_remaining(&self) -> usize {
        self.total_bits.saturating_sub(self.bit_pos)
    }

    /// Read `n` bits from the bitstream (MSB first from the end of data).
    /// Returns the value as a usize.
    #[inline]
    pub fn read_bits(&mut self, n: u32) -> Result<usize, &'static str> {
        if n == 0 {
            return Ok(0);
        }
        let n = n as usize;
        if n > self.bits_remaining() {
            return Err("not enough bits in backward bitstream");
        }

        // Bits are numbered from 0 = LSB of byte[0]. We read n consecutive
        // bits from [low_abs, low_abs + n) where low_abs is the lowest
        // position, giving us the result with low_abs as LSB.
        let low_abs = self.total_bits - n - self.bit_pos;
        let byte_idx = low_abs / 8;
        let bit_idx = low_abs & 7;

        // Load up to 8 bytes from byte_idx into a u64 for bulk extraction.
        let mut buf = [0u8; 8];
        let bytes_avail = self.data.len() - byte_idx;
        let bytes_to_copy = bytes_avail.min(8);
        buf[..bytes_to_copy].copy_from_slice(&self.data[byte_idx..byte_idx + bytes_to_copy]);
        let val = u64::from_le_bytes(buf);

        let result = ((val >> bit_idx) & ((1u64 << n) - 1)) as usize;
        self.bit_pos += n;
        Ok(result)
    }
}

/// Read n bits from a backward bitstream in bulk.
/// Used by Huffman and FSE decoders for peek/read operations.
/// `total_bits` is the number of valid data bits (excluding init marker).
/// `bit_pos` counts bits consumed from the MSB end.
#[inline(always)]
pub(crate) fn read_bits_backward_bulk(
    data: &[u8],
    total_bits: usize,
    bit_pos: usize,
    n: usize,
) -> u64 {
    if n == 0 {
        return 0;
    }
    let low_abs = total_bits - n - bit_pos;
    let byte_idx = low_abs / 8;
    let bit_idx = low_abs & 7;

    let mut buf = [0u8; 8];
    let bytes_avail = data.len() - byte_idx;
    let bytes_to_copy = bytes_avail.min(8);
    buf[..bytes_to_copy].copy_from_slice(&data[byte_idx..byte_idx + bytes_to_copy]);
    let val = u64::from_le_bytes(buf);

    (val >> bit_idx) & ((1u64 << n) - 1)
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
    fn test_dummy_to_check_compilation() {
        assert_eq!(1, 1);
    }

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
    fn test_highest_bit() {
        assert_eq!(highest_bit(1), 0);
        assert_eq!(highest_bit(2), 1);
        assert_eq!(highest_bit(3), 1);
        assert_eq!(highest_bit(4), 2);
        assert_eq!(highest_bit(64), 6);
        assert_eq!(highest_bit(255), 7);
    }
}
