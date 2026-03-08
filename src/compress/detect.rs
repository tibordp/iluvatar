use super::CompressionFormat;

/// Minimum number of bytes needed to detect compression format.
pub const DETECT_MIN_BYTES: usize = 6;

/// Detect the compression format from the first few bytes of a stream.
///
/// Returns `None` if the bytes don't match any known format and aren't
/// long enough to be a tar header. Returns `Some(CompressionFormat::None)`
/// if the data looks like it could be an uncompressed tar.
pub fn detect_format(header: &[u8]) -> Option<CompressionFormat> {
    if header.len() < 2 {
        return None;
    }

    // Gzip: 1f 8b
    if header[0] == 0x1f && header[1] == 0x8b {
        return Some(CompressionFormat::Gzip);
    }

    // Bzip2: 42 5a 68 ("BZh")
    if header.len() >= 3 && header[0] == 0x42 && header[1] == 0x5a && header[2] == 0x68 {
        return Some(CompressionFormat::Bzip2);
    }

    // XZ: fd 37 7a 58 5a 00
    if header.len() >= 6
        && header[0] == 0xfd
        && header[1] == 0x37
        && header[2] == 0x7a
        && header[3] == 0x58
        && header[4] == 0x5a
        && header[5] == 0x00
    {
        return Some(CompressionFormat::Xz);
    }

    // Zstd: 28 b5 2f fd
    if header.len() >= 4
        && header[0] == 0x28
        && header[1] == 0xb5
        && header[2] == 0x2f
        && header[3] == 0xfd
    {
        return Some(CompressionFormat::Zstd);
    }

    // Check for tar magic "ustar" at offset 257
    if header.len() >= 263 && &header[257..262] == b"ustar" {
        return Some(CompressionFormat::None);
    }

    // If we have enough bytes but no match, assume uncompressed
    if header.len() >= DETECT_MIN_BYTES {
        return Some(CompressionFormat::None);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_gzip() {
        assert_eq!(detect_format(&[0x1f, 0x8b, 0x08]), Some(CompressionFormat::Gzip));
    }

    #[test]
    fn test_detect_bzip2() {
        assert_eq!(
            detect_format(&[0x42, 0x5a, 0x68, 0x39]),
            Some(CompressionFormat::Bzip2)
        );
    }

    #[test]
    fn test_detect_xz() {
        assert_eq!(
            detect_format(&[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]),
            Some(CompressionFormat::Xz)
        );
    }

    #[test]
    fn test_detect_zstd() {
        assert_eq!(
            detect_format(&[0x28, 0xb5, 0x2f, 0xfd, 0x00]),
            Some(CompressionFormat::Zstd)
        );
    }

    #[test]
    fn test_detect_uncompressed() {
        // Not a known format, long enough to decide
        assert_eq!(
            detect_format(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            Some(CompressionFormat::None)
        );
    }

    #[test]
    fn test_detect_too_short() {
        assert_eq!(detect_format(&[0x00]), None);
    }
}
