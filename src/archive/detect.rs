use crate::archive::ArchiveFormat;

/// Minimum bytes needed for reliable archive format detection.
/// 263 bytes covers the ustar magic at offset 257 in tar headers.
pub const MIN_DETECT_BYTES: usize = 263;

/// Detect the archive format from decompressed data.
///
/// Returns `None` if there isn't enough data to decide.
/// Needs at least 263 bytes for reliable tar detection (ustar magic
/// at offset 257). Cpio magic is at byte 0, so 6 bytes suffice.
pub fn detect_archive_format(data: &[u8]) -> Option<ArchiveFormat> {
    if data.len() >= 6 {
        // cpio newc: "070701" or "070702" (with CRC)
        if &data[0..6] == b"070701" || &data[0..6] == b"070702" {
            return Some(ArchiveFormat::Cpio);
        }
        // cpio odc: "070707"
        if &data[0..6] == b"070707" {
            return Some(ArchiveFormat::Cpio);
        }
    }
    if data.len() >= 2 {
        // cpio binary: magic 070707 octal = 0x71C7 little-endian or 0xC771 big-endian
        let le = u16::from_le_bytes([data[0], data[1]]);
        let be = u16::from_be_bytes([data[0], data[1]]);
        if le == 0o070707 || be == 0o070707 {
            return Some(ArchiveFormat::Cpio);
        }
    }
    // tar: look for ustar magic at offset 257
    if data.len() >= MIN_DETECT_BYTES {
        if &data[257..262] == b"ustar" {
            return Some(ArchiveFormat::Tar);
        }
        // If we have enough data and no cpio or ustar magic,
        // assume tar (V7 tar has no ustar magic).
        return Some(ArchiveFormat::Tar);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_cpio_newc() {
        let mut data = vec![0u8; 300];
        data[..6].copy_from_slice(b"070701");
        assert_eq!(detect_archive_format(&data), Some(ArchiveFormat::Cpio));
    }

    #[test]
    fn test_detect_cpio_crc() {
        let mut data = vec![0u8; 300];
        data[..6].copy_from_slice(b"070702");
        assert_eq!(detect_archive_format(&data), Some(ArchiveFormat::Cpio));
    }

    #[test]
    fn test_detect_cpio_odc() {
        let mut data = vec![0u8; 300];
        data[..6].copy_from_slice(b"070707");
        assert_eq!(detect_archive_format(&data), Some(ArchiveFormat::Cpio));
    }

    #[test]
    fn test_detect_tar_ustar() {
        let mut data = vec![0u8; 300];
        data[257..262].copy_from_slice(b"ustar");
        assert_eq!(detect_archive_format(&data), Some(ArchiveFormat::Tar));
    }

    #[test]
    fn test_detect_tar_v7() {
        // No ustar magic, but enough data — assume tar
        let data = vec![0u8; 300];
        assert_eq!(detect_archive_format(&data), Some(ArchiveFormat::Tar));
    }

    #[test]
    fn test_detect_insufficient_data() {
        let data = vec![0u8; 10];
        assert_eq!(detect_archive_format(&data), None);
    }
}
