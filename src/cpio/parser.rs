use crate::archive::entry::{ArchiveEntry, EntryType};
use crate::archive::parser::{ArchiveEvent, ArchiveParser};
use crate::cpio::header::{
    self, align4, CpioHeader, CpioSubFormat, NEWC_CRC_MAGIC, NEWC_HEADER_SIZE, NEWC_MAGIC,
    ODC_HEADER_SIZE, ODC_MAGIC, TRAILER_NAME,
};
use crate::error::{Error, Result};
use std::collections::{BTreeMap, HashMap, VecDeque};

/// Maximum accepted filename / symlink-target size. Paths are never
/// anywhere near this; the limit keeps a crafted header from forcing a
/// huge allocation.
const MAX_NAME_SIZE: usize = 1 << 16;

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
        /// Inode and link count, for hardlink resolution at emission time.
        ino: u64,
        nlink: u32,
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
    /// Inode -> path of the data-bearing member, for hardlink resolution.
    resolved_inodes: HashMap<u64, String>,
    /// Zero-size hardlink members seen before their inode's data-bearing
    /// member; emitted (as HardLink) once it arrives. In newc archives the
    /// file data is stored with the LAST member of a hardlink set, so the
    /// earlier members must be deferred. BTreeMap for deterministic order.
    deferred_links: BTreeMap<u64, Vec<ArchiveEntry>>,
    /// Entries ready to be emitted on subsequent feed() calls.
    pending: VecDeque<ArchiveEntry>,
}

impl CpioParser {
    pub fn new() -> Self {
        Self {
            state: CpioState::ReadingHeader,
            header_buf: Vec::with_capacity(NEWC_HEADER_SIZE),
            stream_pos: 0,
            sub_format: None,
            resolved_inodes: HashMap::new(),
            deferred_links: BTreeMap::new(),
            pending: VecDeque::new(),
        }
    }

    /// Hardlink resolution at emission time. Returns the entry to emit now,
    /// or `None` if it was deferred until its inode's data-bearing member
    /// arrives (which also queues the deferred members onto `pending`).
    fn apply_hardlink_policy(
        &mut self,
        mut entry: ArchiveEntry,
        ino: u64,
        nlink: u32,
    ) -> Option<ArchiveEntry> {
        if entry.entry_type != EntryType::Regular || nlink <= 1 {
            return Some(entry);
        }
        if entry.size > 0 {
            // Data-bearing member: this is the canonical path for the inode.
            self.resolved_inodes.insert(ino, entry.path.clone());
            if let Some(deferred) = self.deferred_links.remove(&ino) {
                for mut d in deferred {
                    d.entry_type = EntryType::HardLink;
                    d.link_target = Some(entry.path.clone());
                    self.pending.push_back(d);
                }
            }
            Some(entry)
        } else if let Some(path) = self.resolved_inodes.get(&ino) {
            // Data member already seen (data-first layout).
            entry.entry_type = EntryType::HardLink;
            entry.link_target = Some(path.clone());
            Some(entry)
        } else {
            // Data member not seen yet (the usual newc layout): defer.
            self.deferred_links.entry(ino).or_default().push(entry);
            None
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

        let mut consumed = 0usize;

        // Detect the sub-format from the 6 magic bytes BEFORE deciding how
        // many header bytes to read; odc headers are shorter than newc ones,
        // so buffering a newc-sized header first would over-consume when the
        // header arrives in small chunks.
        if self.sub_format.is_none() {
            let need_magic = 6usize.saturating_sub(self.header_buf.len());
            if need_magic > 0 {
                let take = data.len().min(need_magic);
                self.header_buf.extend_from_slice(&data[..take]);
                self.stream_pos += take as u64;
                consumed += take;
                if self.header_buf.len() < 6 {
                    return Ok((consumed, ArchiveEvent::NeedData));
                }
            }
            self.sub_format = Some(match &self.header_buf[0..6] {
                m if m == NEWC_MAGIC => CpioSubFormat::Newc,
                m if m == NEWC_CRC_MAGIC => CpioSubFormat::NewcCrc,
                m if m == ODC_MAGIC => CpioSubFormat::Odc,
                other => {
                    return Err(Error::InvalidCpioHeader(format!(
                        "unrecognized cpio magic: {:?}",
                        other
                    )));
                }
            });
        }

        let header_size = self.header_size();
        let needed = header_size - self.header_buf.len();
        let available = (data.len() - consumed).min(needed);
        self.header_buf
            .extend_from_slice(&data[consumed..consumed + available]);
        self.stream_pos += available as u64;
        consumed += available;

        if self.header_buf.len() < header_size {
            return Ok((consumed, ArchiveEvent::NeedData));
        }

        self.process_header(consumed)
    }

    fn process_header(&mut self, consumed: usize) -> Result<(usize, ArchiveEvent)> {
        let hdr = match self.sub_format {
            Some(CpioSubFormat::Odc) => header::parse_odc_header(&self.header_buf)?,
            _ => header::parse_newc_header(&self.header_buf)?,
        };

        let namesize = hdr.namesize as usize;
        if namesize > MAX_NAME_SIZE {
            return Err(Error::InvalidCpioHeader(format!(
                "implausible namesize {}",
                namesize
            )));
        }
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
            // Flush hardlink members whose data-bearing member never arrived
            // (nonstandard/malformed archives) so they are not lost; they
            // stay as the zero-size regular entries the archive declared.
            let deferred = std::mem::take(&mut self.deferred_links);
            self.pending.extend(deferred.into_values().flatten());
            self.state = CpioState::End;
            if let Some(entry) = self.pending.pop_front() {
                return Ok((take, ArchiveEvent::Entry(entry)));
            }
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

        let entry = ArchiveEntry {
            path: filename,
            size: hdr.filesize,
            entry_type,
            mode: hdr.mode & 0o7777, // Strip S_IFMT bits, keep permission bits
            uid: hdr.uid,
            gid: hdr.gid,
            mtime: hdr.mtime,
            link_target: None,
            data_offset,
        };

        if name_pad > 0 {
            // Need to skip padding before we can process data
            self.state = CpioState::SkippingNamePad {
                entry,
                remaining: name_pad,
                ino: hdr.ino,
                nlink: hdr.nlink,
            };
            return Ok((take, ArchiveEvent::NeedData));
        }

        // No padding — go directly to data handling
        self.transition_to_data(entry, &hdr)
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
        let (mut entry, ino, nlink) = match std::mem::replace(&mut self.state, CpioState::End) {
            CpioState::SkippingNamePad {
                entry, ino, nlink, ..
            } => (entry, ino, nlink),
            _ => unreachable!(),
        };
        entry.data_offset = self.stream_pos;

        // We need the header info to determine filesize for transition
        // but we already stored it in entry.size
        let filesize = entry.size;
        let entry_type = entry.entry_type;

        if entry_type == EntryType::SymLink && filesize > 0 {
            if filesize as usize > MAX_NAME_SIZE {
                return Err(Error::InvalidCpioHeader(format!(
                    "implausible symlink target size {}",
                    filesize
                )));
            }
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
            match self.apply_hardlink_policy(entry, ino, nlink) {
                Some(entry) => Ok((skip, ArchiveEvent::Entry(entry))),
                None => Ok((skip, ArchiveEvent::NeedData)),
            }
        } else {
            self.state = CpioState::ReadingHeader;
            match self.apply_hardlink_policy(entry, ino, nlink) {
                Some(entry) => Ok((skip, ArchiveEvent::Entry(entry))),
                None => Ok((skip, ArchiveEvent::NeedData)),
            }
        }
    }

    fn transition_to_data(
        &mut self,
        mut entry: ArchiveEntry,
        hdr: &CpioHeader,
    ) -> Result<ArchiveEvent> {
        entry.data_offset = self.stream_pos;

        if entry.entry_type == EntryType::SymLink && hdr.filesize > 0 {
            if hdr.filesize as usize > MAX_NAME_SIZE {
                return Err(Error::InvalidCpioHeader(format!(
                    "implausible symlink target size {}",
                    hdr.filesize
                )));
            }
            self.state = CpioState::ReadingLinkTarget {
                entry,
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
            match self.apply_hardlink_policy(entry, hdr.ino, hdr.nlink) {
                Some(entry) => Ok(ArchiveEvent::Entry(entry)),
                None => Ok(ArchiveEvent::NeedData),
            }
        } else {
            self.state = CpioState::ReadingHeader;
            match self.apply_hardlink_policy(entry, hdr.ino, hdr.nlink) {
                Some(entry) => Ok(ArchiveEvent::Entry(entry)),
                None => Ok(ArchiveEvent::NeedData),
            }
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
        // Deliver any entries queued by hardlink resolution first.
        if let Some(entry) = self.pending.pop_front() {
            return Ok((0, ArchiveEvent::Entry(entry)));
        }
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

    // ─── Hardening & hardlink tests ───

    /// Write a single newc record with full control over the header fields.
    #[allow(clippy::too_many_arguments)]
    fn write_newc_record(
        archive: &mut Vec<u8>,
        path: &str,
        content: &[u8],
        ino: u64,
        mode: u32,
        nlink: u32,
        namesize_override: Option<u32>,
        filesize_override: Option<u64>,
    ) {
        let namesize = namesize_override.unwrap_or(path.len() as u32 + 1);
        let filesize = filesize_override.unwrap_or(content.len() as u64);
        let header =
            format!(
            "070701{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}",
            ino, mode, 1000u32, 1000u32, nlink, 1700000000u32, filesize, 0u32, 0u32, 0u32, 0u32,
            namesize, 0u32,
        );
        archive.extend_from_slice(header.as_bytes());
        archive.extend_from_slice(path.as_bytes());
        archive.push(0);
        let total = 110 + path.len() + 1;
        let padded = (total + 3) & !3;
        archive.resize(archive.len() + padded - total, 0);
        archive.extend_from_slice(content);
        let data_padded = (content.len() + 3) & !3;
        archive.resize(archive.len() + data_padded - content.len(), 0);
    }

    fn write_newc_trailer(archive: &mut Vec<u8>) {
        write_newc_record(archive, "TRAILER!!!", b"", 0, 0, 1, None, None);
    }

    /// Create an odc-format cpio archive in memory.
    fn create_odc_archive(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut archive = Vec::new();
        let mut write_record = |path: &str, content: &[u8], ino: u64| {
            let header = format!(
                "070707{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:011o}{:06o}{:011o}",
                0u32,           // dev
                ino,            // ino
                0o100644u32,    // mode
                1000u32,        // uid
                1000u32,        // gid
                1u32,           // nlink
                0u32,           // rdev
                1700000000u64,  // mtime
                path.len() + 1, // namesize
                content.len(),  // filesize
            );
            assert_eq!(header.len(), 76);
            archive.extend_from_slice(header.as_bytes());
            archive.extend_from_slice(path.as_bytes());
            archive.push(0);
            archive.extend_from_slice(content);
        };
        for (ino, (path, content)) in (1u64..).zip(files.iter()) {
            write_record(path, content, ino);
        }
        write_record("TRAILER!!!", b"", 0);
        archive
    }

    /// Drive the parser over data in fixed-size chunks; collect entries.
    fn parse_chunked(data: &[u8], chunk: usize) -> Result<Vec<ArchiveEntry>> {
        let mut parser = CpioParser::new();
        let mut offset = 0;
        let mut entries = Vec::new();
        loop {
            let end = (offset + chunk).min(data.len());
            let (consumed, event) = parser.feed(&data[offset..end])?;
            offset += consumed;
            match event {
                ArchiveEvent::Entry(entry) => entries.push(entry),
                ArchiveEvent::NeedData => {
                    if offset >= data.len() {
                        break;
                    }
                }
                ArchiveEvent::EndOfArchive => break,
            }
        }
        Ok(entries)
    }

    #[test]
    fn test_odc_byte_by_byte() {
        // odc headers are shorter than newc; feeding one byte at a time used
        // to underflow the consumed-bytes computation once the sub-format
        // was detected mid-header.
        let archive = create_odc_archive(&[("a.txt", b"hello"), ("b.txt", b"world!")]);
        for chunk in [1, 2, 3, 7, 33, 75, 76, 77] {
            let entries = parse_chunked(&archive, chunk).unwrap();
            assert_eq!(entries.len(), 2, "chunk size {}", chunk);
            assert_eq!(entries[0].path, "a.txt");
            assert_eq!(entries[0].size, 5);
            assert_eq!(entries[1].path, "b.txt");
            assert_eq!(entries[1].size, 6);
        }
    }

    #[test]
    fn test_newc_hardlinks_data_last() {
        // newc stores hardlink data with the LAST member of the set; the
        // earlier members are zero-size. All members must resolve.
        let mut archive = Vec::new();
        write_newc_record(&mut archive, "dir/link1", b"", 42, 0o100644, 3, None, None);
        write_newc_record(&mut archive, "dir/link2", b"", 42, 0o100644, 3, None, None);
        write_newc_record(
            &mut archive,
            "dir/last",
            b"shared content",
            42,
            0o100644,
            3,
            None,
            None,
        );
        write_newc_record(
            &mut archive,
            "other.txt",
            b"xyz",
            43,
            0o100644,
            1,
            None,
            None,
        );
        write_newc_trailer(&mut archive);

        for chunk in [usize::MAX, 1, 13] {
            let entries = parse_chunked(&archive, chunk.min(archive.len())).unwrap();
            assert_eq!(entries.len(), 4, "chunk {}", chunk);

            let by_path: std::collections::HashMap<_, _> =
                entries.iter().map(|e| (e.path.as_str(), e)).collect();

            let last = by_path["dir/last"];
            assert_eq!(last.entry_type, EntryType::Regular);
            assert_eq!(last.size, 14);

            for link in ["dir/link1", "dir/link2"] {
                let e = by_path[link];
                assert_eq!(e.entry_type, EntryType::HardLink, "{}", link);
                assert_eq!(e.link_target.as_deref(), Some("dir/last"), "{}", link);
            }

            assert_eq!(by_path["other.txt"].entry_type, EntryType::Regular);
        }
    }

    #[test]
    fn test_newc_hardlinks_data_first() {
        // Nonstandard layout: data-bearing member first. Later zero-size
        // members must immediately resolve as hardlinks to it.
        let mut archive = Vec::new();
        write_newc_record(
            &mut archive,
            "first",
            b"data here",
            7,
            0o100644,
            2,
            None,
            None,
        );
        write_newc_record(&mut archive, "second", b"", 7, 0o100644, 2, None, None);
        write_newc_trailer(&mut archive);

        let entries = parse_chunked(&archive, archive.len()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, "first");
        assert_eq!(entries[0].entry_type, EntryType::Regular);
        assert_eq!(entries[1].path, "second");
        assert_eq!(entries[1].entry_type, EntryType::HardLink);
        assert_eq!(entries[1].link_target.as_deref(), Some("first"));
    }

    #[test]
    fn test_newc_hardlink_unresolved_flushed_at_trailer() {
        // A hardlink member whose data-bearing member never appears must
        // still be emitted (as the zero-size entry the archive declared),
        // not silently dropped.
        let mut archive = Vec::new();
        write_newc_record(&mut archive, "orphan", b"", 9, 0o100644, 2, None, None);
        write_newc_trailer(&mut archive);

        let entries = parse_chunked(&archive, archive.len()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "orphan");
        assert_eq!(entries[0].size, 0);
    }

    #[test]
    fn test_implausible_namesize_rejected() {
        let mut archive = Vec::new();
        write_newc_record(
            &mut archive,
            "x",
            b"",
            1,
            0o100644,
            1,
            Some(0x40000000), // 1 GiB namesize
            None,
        );
        assert!(parse_chunked(&archive, archive.len()).is_err());
    }

    #[test]
    fn test_implausible_symlink_target_rejected() {
        let mut archive = Vec::new();
        write_newc_record(
            &mut archive,
            "link",
            b"",
            1,
            0o120777, // symlink mode
            1,
            None,
            Some(1 << 32), // 4 GiB "target"
        );
        assert!(parse_chunked(&archive, archive.len()).is_err());
    }
}
