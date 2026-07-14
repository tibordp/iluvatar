use crate::archive::entry::{ArchiveEntry, EntryType};
use crate::archive::parser::{ArchiveEvent, ArchiveParser};
use crate::cpio::header::{
    self, align4, CpioHeader, CpioSubFormat, NEWC_CRC_MAGIC, NEWC_HEADER_SIZE, NEWC_MAGIC,
    ODC_HEADER_SIZE, ODC_MAGIC, TRAILER_NAME,
};
use crate::error::{Error, Result};
use std::collections::HashMap;

/// Internal parser state.
enum CpioState {
    /// Reading the fixed-size header.
    ReadingHeader,
    /// Reading the filename after the header.
    ReadingFilename {
        header: CpioHeader,
        /// How many filename bytes we still need.
        remaining: usize,
        buf: Vec<u8>,
    },
    /// Skipping padding after the filename (newc only).
    SkippingNamePad {
        entry: ArchiveEntry,
        remaining: usize,
    },
    /// Reading symlink target (stored as file data in cpio).
    ReadingLinkTarget {
        entry: ArchiveEntry,
        remaining: usize,
        buf: Vec<u8>,
    },
    /// Skipping file data we don't need (non-symlink entries).
    SkippingData { remaining: u64 },
    /// Skipping padding after file data (newc only).
    SkippingDataPad { remaining: usize },
    /// End of archive.
    End,
}

/// Incremental, sans-I/O cpio parser.
///
/// Supports newc, newc-CRC, and odc sub-formats. The sub-format is
/// auto-detected from the first header's magic bytes.
pub struct CpioParser {
    state: CpioState,
    /// Buffer for accumulating a header.
    header_buf: Vec<u8>,
    /// Current position in the uncompressed stream.
    stream_pos: u64,
    /// Detected sub-format (set after first header).
    sub_format: Option<CpioSubFormat>,
    /// Map inode -> first path, for hardlink resolution.
    inode_paths: HashMap<u64, String>,
}

impl CpioParser {
    pub fn new() -> Self {
        Self {
            state: CpioState::ReadingHeader,
            header_buf: Vec::with_capacity(NEWC_HEADER_SIZE),
            stream_pos: 0,
            sub_format: None,
            inode_paths: HashMap::new(),
        }
    }

    /// Size of the current format's header.
    fn header_size(&self) -> usize {
        match self.sub_format {
            Some(CpioSubFormat::Odc) => ODC_HEADER_SIZE,
            _ => NEWC_HEADER_SIZE, // newc, newc-crc, or unknown (assume newc)
        }
    }

    /// Whether the current format uses 4-byte alignment padding.
    fn uses_alignment(&self) -> bool {
        match self.sub_format {
            Some(CpioSubFormat::Odc) => false,
            _ => true, // newc and newc-crc use 4-byte alignment
        }
    }

    fn feed_header(&mut self, data: &[u8]) -> Result<(usize, ArchiveEvent)> {
        if data.is_empty() {
            return Ok((0, ArchiveEvent::NeedData));
        }

        let header_size = self.header_size();
        let needed = header_size - self.header_buf.len();
        let available = data.len().min(needed);
        self.header_buf.extend_from_slice(&data[..available]);
        self.stream_pos += available as u64;

        if self.header_buf.len() < header_size {
            return Ok((available, ArchiveEvent::NeedData));
        }

        // Detect sub-format from magic if this is the first header
        if self.sub_format.is_none() && self.header_buf.len() >= 6 {
            if &self.header_buf[0..6] == NEWC_MAGIC {
                self.sub_format = Some(CpioSubFormat::Newc);
            } else if &self.header_buf[0..6] == NEWC_CRC_MAGIC {
                self.sub_format = Some(CpioSubFormat::NewcCrc);
            } else if &self.header_buf[0..6] == ODC_MAGIC {
                self.sub_format = Some(CpioSubFormat::Odc);
                // odc header is shorter — if we over-read, we'll handle below
                if self.header_buf.len() > ODC_HEADER_SIZE {
                    // We read too many bytes (assumed newc size).
                    // Return only what we need and rewind.
                    let excess = self.header_buf.len() - ODC_HEADER_SIZE;
                    self.stream_pos -= excess as u64;
                    self.header_buf.truncate(ODC_HEADER_SIZE);
                    let consumed = available - excess;
                    return self.process_header(consumed);
                } else if self.header_buf.len() < ODC_HEADER_SIZE {
                    // Need more data for odc header
                    return Ok((available, ArchiveEvent::NeedData));
                }
            } else {
                return Err(Error::InvalidCpioHeader(format!(
                    "unrecognized cpio magic: {:?}",
                    &self.header_buf[0..6]
                )));
            }
        }

        self.process_header(available)
    }

    fn process_header(&mut self, consumed: usize) -> Result<(usize, ArchiveEvent)> {
        let hdr = match self.sub_format {
            Some(CpioSubFormat::Odc) => header::parse_odc_header(&self.header_buf)?,
            _ => header::parse_newc_header(&self.header_buf)?,
        };

        let namesize = hdr.namesize as usize;
        self.header_buf.clear();

        self.state = CpioState::ReadingFilename {
            header: hdr,
            remaining: namesize,
            buf: Vec::with_capacity(namesize),
        };

        Ok((consumed, ArchiveEvent::NeedData))
    }

    fn feed_filename(&mut self, data: &[u8]) -> Result<(usize, ArchiveEvent)> {
        if data.is_empty() {
            return Ok((0, ArchiveEvent::NeedData));
        }

        let (header, remaining, buf) = match &mut self.state {
            CpioState::ReadingFilename {
                header,
                remaining,
                buf,
            } => (header, remaining, buf),
            _ => unreachable!(),
        };

        let take = data.len().min(*remaining);
        buf.extend_from_slice(&data[..take]);
        *remaining -= take;
        self.stream_pos += take as u64;

        if *remaining > 0 {
            return Ok((take, ArchiveEvent::NeedData));
        }

        // Filename complete — extract the owned values
        let filename = String::from_utf8_lossy(buf)
            .trim_end_matches('\0')
            .to_string();
        let hdr = header.clone();
        let entry_type = header::entry_type_from_mode(hdr.mode);

        // Check for end-of-archive trailer
        if filename == TRAILER_NAME {
            self.state = CpioState::End;
            return Ok((take, ArchiveEvent::EndOfArchive));
        }

        // Calculate padding after header+filename (newc: align to 4 bytes)
        let name_pad = if self.uses_alignment() {
            let total_header_name = self.header_size() + hdr.namesize as usize;
            align4(total_header_name) - total_header_name
        } else {
            0
        };

        // Data starts after filename + alignment padding
        let data_offset = self.stream_pos + name_pad as u64;

        // Handle hardlinks via inode tracking
        let link_target = if entry_type == EntryType::Regular && hdr.nlink > 1 {
            if hdr.filesize == 0 {
                // This is a hardlink to a previously seen inode
                self.inode_paths.get(&hdr.ino).cloned()
            } else {
                // First occurrence — record the path
                self.inode_paths.insert(hdr.ino, filename.clone());
                None
            }
        } else {
            None
        };

        let is_hardlink = link_target.is_some() && hdr.filesize == 0;
        let actual_entry_type = if is_hardlink {
            EntryType::HardLink
        } else {
            entry_type
        };

        let mut entry = ArchiveEntry {
            path: filename,
            size: hdr.filesize,
            entry_type: actual_entry_type,
            mode: hdr.mode & 0o7777, // Strip S_IFMT bits, keep permission bits
            uid: hdr.uid,
            gid: hdr.gid,
            mtime: hdr.mtime,
            link_target,
            data_offset,
        };

        if name_pad > 0 {
            // Need to skip padding before we can process data
            self.state = CpioState::SkippingNamePad {
                entry,
                remaining: name_pad,
            };
            return Ok((take, ArchiveEvent::NeedData));
        }

        // No padding — go directly to data handling
        self.transition_to_data(&mut entry, &hdr)
            .map(|event| (take, event))
    }

    fn feed_skip_name_pad(&mut self, data: &[u8]) -> Result<(usize, ArchiveEvent)> {
        if data.is_empty() {
            return Ok((0, ArchiveEvent::NeedData));
        }

        let remaining = match &mut self.state {
            CpioState::SkippingNamePad { remaining, .. } => remaining,
            _ => unreachable!(),
        };

        let skip = data.len().min(*remaining);
        *remaining -= skip;
        self.stream_pos += skip as u64;

        if *remaining > 0 {
            return Ok((skip, ArchiveEvent::NeedData));
        }

        // Padding done — update data_offset to current position
        let mut entry = match std::mem::replace(&mut self.state, CpioState::End) {
            CpioState::SkippingNamePad { entry, .. } => entry,
            _ => unreachable!(),
        };
        entry.data_offset = self.stream_pos;

        // We need the header info to determine filesize for transition
        // but we already stored it in entry.size
        let filesize = entry.size;
        let entry_type = entry.entry_type;

        if entry_type == EntryType::SymLink && filesize > 0 {
            self.state = CpioState::ReadingLinkTarget {
                entry,
                remaining: filesize as usize,
                buf: Vec::with_capacity(filesize as usize),
            };
            Ok((skip, ArchiveEvent::NeedData))
        } else if filesize > 0 {
            // Skip file data
            let data_pad = if self.uses_alignment() {
                align4(filesize as usize) - filesize as usize
            } else {
                0
            };
            let total_skip = filesize + data_pad as u64;
            self.state = CpioState::SkippingData {
                remaining: total_skip,
            };
            Ok((skip, ArchiveEvent::Entry(entry)))
        } else {
            self.state = CpioState::ReadingHeader;
            Ok((skip, ArchiveEvent::Entry(entry)))
        }
    }

    fn transition_to_data(
        &mut self,
        entry: &mut ArchiveEntry,
        hdr: &CpioHeader,
    ) -> Result<ArchiveEvent> {
        entry.data_offset = self.stream_pos;

        if entry.entry_type == EntryType::SymLink && hdr.filesize > 0 {
            let entry_clone = entry.clone();
            self.state = CpioState::ReadingLinkTarget {
                entry: entry_clone,
                remaining: hdr.filesize as usize,
                buf: Vec::with_capacity(hdr.filesize as usize),
            };
            Ok(ArchiveEvent::NeedData)
        } else if hdr.filesize > 0 {
            let data_pad = if self.uses_alignment() {
                align4(hdr.filesize as usize) - hdr.filesize as usize
            } else {
                0
            };
            let total_skip = hdr.filesize + data_pad as u64;
            self.state = CpioState::SkippingData {
                remaining: total_skip,
            };
            Ok(ArchiveEvent::Entry(entry.clone()))
        } else {
            self.state = CpioState::ReadingHeader;
            Ok(ArchiveEvent::Entry(entry.clone()))
        }
    }

    fn feed_link_target(&mut self, data: &[u8]) -> Result<(usize, ArchiveEvent)> {
        if data.is_empty() {
            return Ok((0, ArchiveEvent::NeedData));
        }

        let (remaining, buf) = match &mut self.state {
            CpioState::ReadingLinkTarget { remaining, buf, .. } => (remaining, buf),
            _ => unreachable!(),
        };

        let take = data.len().min(*remaining);
        buf.extend_from_slice(&data[..take]);
        *remaining -= take;
        self.stream_pos += take as u64;

        if *remaining > 0 {
            return Ok((take, ArchiveEvent::NeedData));
        }

        // Link target complete
        let target = String::from_utf8_lossy(buf).to_string();
        let mut entry = match std::mem::replace(&mut self.state, CpioState::End) {
            CpioState::ReadingLinkTarget { entry, .. } => entry,
            _ => unreachable!(),
        };
        entry.link_target = Some(target);
        // Symlink data is not "file data" for indexing, so set size to 0
        entry.size = 0;

        // Skip data padding if needed
        let original_filesize = self.stream_pos - entry.data_offset;
        let data_pad = if self.uses_alignment() {
            align4(original_filesize as usize) - original_filesize as usize
        } else {
            0
        };

        if data_pad > 0 {
            self.state = CpioState::SkippingDataPad {
                remaining: data_pad,
            };
        } else {
            self.state = CpioState::ReadingHeader;
        }

        Ok((take, ArchiveEvent::Entry(entry)))
    }

    fn feed_skip_data(&mut self, data: &[u8]) -> Result<(usize, ArchiveEvent)> {
        if data.is_empty() {
            return Ok((0, ArchiveEvent::NeedData));
        }

        let remaining = match &mut self.state {
            CpioState::SkippingData { remaining } => remaining,
            _ => unreachable!(),
        };

        let skip = (data.len() as u64).min(*remaining) as usize;
        *remaining -= skip as u64;
        self.stream_pos += skip as u64;

        if *remaining == 0 {
            self.state = CpioState::ReadingHeader;
        }

        Ok((skip, ArchiveEvent::NeedData))
    }

    fn feed_skip_data_pad(&mut self, data: &[u8]) -> Result<(usize, ArchiveEvent)> {
        if data.is_empty() {
            return Ok((0, ArchiveEvent::NeedData));
        }

        let remaining = match &mut self.state {
            CpioState::SkippingDataPad { remaining } => remaining,
            _ => unreachable!(),
        };

        let skip = data.len().min(*remaining);
        *remaining -= skip;
        self.stream_pos += skip as u64;

        if *remaining == 0 {
            self.state = CpioState::ReadingHeader;
        }

        Ok((skip, ArchiveEvent::NeedData))
    }
}

impl Default for CpioParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArchiveParser for CpioParser {
    fn feed(&mut self, data: &[u8]) -> Result<(usize, ArchiveEvent)> {
        match &self.state {
            CpioState::ReadingHeader => self.feed_header(data),
            CpioState::ReadingFilename { .. } => self.feed_filename(data),
            CpioState::SkippingNamePad { .. } => self.feed_skip_name_pad(data),
            CpioState::ReadingLinkTarget { .. } => self.feed_link_target(data),
            CpioState::SkippingData { .. } => self.feed_skip_data(data),
            CpioState::SkippingDataPad { .. } => self.feed_skip_data_pad(data),
            CpioState::End => Ok((0, ArchiveEvent::EndOfArchive)),
        }
    }

    fn stream_pos(&self) -> u64 {
        self.stream_pos
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a newc-format cpio archive in memory.
    fn create_newc_archive(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut archive = Vec::new();

        for (ino, (path, content)) in (1u64..).zip(files.iter()) {
            let namesize = path.len() + 1; // include null terminator
            let filesize = content.len();

            // Write header
            let header = format!(
                "070701\
                 {:08X}\
                 {:08X}\
                 {:08X}\
                 {:08X}\
                 {:08X}\
                 {:08X}\
                 {:08X}\
                 {:08X}\
                 {:08X}\
                 {:08X}\
                 {:08X}\
                 {:08X}\
                 {:08X}",
                ino,
                0o100644u32,   // mode: regular file
                1000u32,       // uid
                1000u32,       // gid
                1u32,          // nlink
                1700000000u32, // mtime
                filesize,
                0u32, // devmajor
                0u32, // devminor
                0u32, // rdevmajor
                0u32, // rdevminor
                namesize,
                0u32, // check
            );
            archive.extend_from_slice(header.as_bytes());

            // Write filename + null
            archive.extend_from_slice(path.as_bytes());
            archive.push(0);

            // Pad header+name to 4-byte boundary
            let total = 110 + namesize;
            let padded = (total + 3) & !3;
            archive.resize(archive.len() + padded - total, 0);

            // Write file data
            archive.extend_from_slice(content);

            // Pad data to 4-byte boundary
            let data_padded = (filesize + 3) & !3;
            archive.resize(archive.len() + data_padded - filesize, 0);
        }

        // Trailer
        let trailer_name = "TRAILER!!!";
        let namesize = trailer_name.len() + 1;
        let header = format!(
            "070701\
             {:08X}\
             {:08X}\
             {:08X}\
             {:08X}\
             {:08X}\
             {:08X}\
             {:08X}\
             {:08X}\
             {:08X}\
             {:08X}\
             {:08X}\
             {:08X}\
             {:08X}",
            0u32, // ino
            0u32, // mode
            0u32, // uid
            0u32, // gid
            1u32, // nlink
            0u32, // mtime
            0u32, // filesize
            0u32, // devmajor
            0u32, // devminor
            0u32, // rdevmajor
            0u32, // rdevminor
            namesize,
            0u32, // check
        );
        archive.extend_from_slice(header.as_bytes());
        archive.extend_from_slice(trailer_name.as_bytes());
        archive.push(0);
        let total = 110 + namesize;
        let padded = (total + 3) & !3;
        archive.resize(archive.len() + padded - total, 0);

        archive
    }

    #[test]
    fn test_parse_single_file() {
        let archive = create_newc_archive(&[("hello.txt", b"Hello, world!")]);
        let mut parser = CpioParser::new();
        let mut offset = 0;
        let mut entries = Vec::new();

        loop {
            let (consumed, event) = parser.feed(&archive[offset..]).unwrap();
            offset += consumed;
            match event {
                ArchiveEvent::Entry(entry) => entries.push(entry),
                ArchiveEvent::NeedData => {
                    if offset >= archive.len() {
                        break;
                    }
                }
                ArchiveEvent::EndOfArchive => break,
            }
        }

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "hello.txt");
        assert_eq!(entries[0].size, 13);
        assert_eq!(entries[0].entry_type, EntryType::Regular);
        assert_eq!(entries[0].mode, 0o644);
    }

    #[test]
    fn test_parse_multiple_files() {
        let archive = create_newc_archive(&[
            ("file1.txt", b"content1"),
            ("file2.txt", b"longer content here"),
        ]);
        let mut parser = CpioParser::new();
        let mut offset = 0;
        let mut entries = Vec::new();

        loop {
            let (consumed, event) = parser.feed(&archive[offset..]).unwrap();
            offset += consumed;
            match event {
                ArchiveEvent::Entry(entry) => entries.push(entry),
                ArchiveEvent::NeedData => {
                    if offset >= archive.len() {
                        break;
                    }
                }
                ArchiveEvent::EndOfArchive => break,
            }
        }

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, "file1.txt");
        assert_eq!(entries[0].size, 8);
        assert_eq!(entries[1].path, "file2.txt");
        assert_eq!(entries[1].size, 19);
    }

    #[test]
    fn test_parse_byte_by_byte() {
        let archive = create_newc_archive(&[("test.txt", b"test data")]);
        let mut parser = CpioParser::new();
        let mut offset = 0;
        let mut entries = Vec::new();

        while offset < archive.len() {
            let (consumed, event) = parser.feed(&archive[offset..offset + 1]).unwrap();
            offset += consumed;
            match event {
                ArchiveEvent::Entry(entry) => entries.push(entry),
                ArchiveEvent::NeedData => {}
                ArchiveEvent::EndOfArchive => break,
            }
        }

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "test.txt");
    }

    #[test]
    fn test_parse_empty_archive() {
        // Just a trailer
        let archive = create_newc_archive(&[]);
        let mut parser = CpioParser::new();
        let mut offset = 0;
        let mut found_end = false;

        loop {
            let (consumed, event) = parser.feed(&archive[offset..]).unwrap();
            offset += consumed;
            match event {
                ArchiveEvent::EndOfArchive => {
                    found_end = true;
                    break;
                }
                ArchiveEvent::NeedData if offset >= archive.len() => {
                    break;
                }
                _ => {}
            }
        }

        assert!(found_end);
    }

    #[test]
    fn test_data_offset_tracking() {
        let archive = create_newc_archive(&[("data.bin", b"0123456789")]);
        let mut parser = CpioParser::new();
        let mut offset = 0;
        let mut entries = Vec::new();

        loop {
            let (consumed, event) = parser.feed(&archive[offset..]).unwrap();
            offset += consumed;
            match event {
                ArchiveEvent::Entry(entry) => entries.push(entry),
                ArchiveEvent::NeedData => {
                    if offset >= archive.len() {
                        break;
                    }
                }
                ArchiveEvent::EndOfArchive => break,
            }
        }

        assert_eq!(entries.len(), 1);
        let data_offset = entries[0].data_offset as usize;
        // Verify data is at the reported offset
        assert_eq!(&archive[data_offset..data_offset + 10], b"0123456789");
    }

    #[test]
    fn test_directory_entry() {
        let mut archive = Vec::new();

        // Directory entry
        let dirname = "mydir";
        let namesize = dirname.len() + 1;
        let header = format!(
            "070701\
             {:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}\
             {:08X}{:08X}{:08X}{:08X}{:08X}{:08X}",
            1u32,
            0o040755u32, // mode: directory
            1000u32,
            1000u32,
            2u32,
            1700000000u32,
            0u32,
            0u32,
            0u32,
            0u32,
            0u32,
            namesize,
            0u32,
        );
        archive.extend_from_slice(header.as_bytes());
        archive.extend_from_slice(dirname.as_bytes());
        archive.push(0);
        let total = 110 + namesize;
        let padded = (total + 3) & !3;
        archive.resize(archive.len() + padded - total, 0);

        // Trailer
        let trailer_name = "TRAILER!!!";
        let namesize = trailer_name.len() + 1;
        let trailer_header = format!(
            "070701\
             {:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}\
             {:08X}{:08X}{:08X}{:08X}{:08X}{:08X}",
            0u32, 0u32, 0u32, 0u32, 1u32, 0u32, 0u32, 0u32, 0u32, 0u32, 0u32, namesize, 0u32,
        );
        archive.extend_from_slice(trailer_header.as_bytes());
        archive.extend_from_slice(trailer_name.as_bytes());
        archive.push(0);
        let total = 110 + namesize;
        let padded = (total + 3) & !3;
        archive.resize(archive.len() + padded - total, 0);

        let mut parser = CpioParser::new();
        let mut offset = 0;
        let mut entries = Vec::new();

        loop {
            let (consumed, event) = parser.feed(&archive[offset..]).unwrap();
            offset += consumed;
            match event {
                ArchiveEvent::Entry(entry) => entries.push(entry),
                ArchiveEvent::NeedData => {
                    if offset >= archive.len() {
                        break;
                    }
                }
                ArchiveEvent::EndOfArchive => break,
            }
        }

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "mydir");
        assert_eq!(entries[0].entry_type, EntryType::Directory);
        assert_eq!(entries[0].mode, 0o755);
    }
}
