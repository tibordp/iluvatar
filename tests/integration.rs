use std::io::Write;
use supertar::archive::ArchiveFormat;
use supertar::compress::CompressionFormat;
use supertar::engine::request::EngineRequest;
use supertar::engine::state_machine::{IndexingEngine, ReadEngine, DEFAULT_CHECKPOINT_INTERVAL};
use supertar::index::store::ArchiveIndex;
use supertar::SyncArchive;
use tempfile::NamedTempFile;

// ─── Helpers ───

/// Create a tar archive (uncompressed) in memory with the given files.
fn create_tar_bytes(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, content) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_uid(1000);
        header.set_gid(1000);
        header.set_mtime(1700000000);
        header.set_cksum();
        builder
            .append_data(&mut header, *path, &content[..])
            .unwrap();
    }
    builder.finish().unwrap();
    builder.into_inner().unwrap()
}

/// Create a gzip-compressed tar archive.
fn create_tar_gz(files: &[(&str, &[u8])]) -> Vec<u8> {
    let tar_data = create_tar_bytes(files);
    let mut encoder =
        flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&tar_data).unwrap();
    encoder.finish().unwrap()
}

/// Create a bzip2-compressed tar archive.
fn create_tar_bz2(files: &[(&str, &[u8])]) -> Vec<u8> {
    let tar_data = create_tar_bytes(files);
    let mut encoder =
        bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
    encoder.write_all(&tar_data).unwrap();
    encoder.finish().unwrap()
}

/// Create an xz-compressed tar archive.
fn create_tar_xz(files: &[(&str, &[u8])]) -> Vec<u8> {
    let tar_data = create_tar_bytes(files);
    let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 6);
    encoder.write_all(&tar_data).unwrap();
    encoder.finish().unwrap()
}

/// Create a zstd-compressed tar archive.
fn create_tar_zst(files: &[(&str, &[u8])]) -> Vec<u8> {
    let tar_data = create_tar_bytes(files);
    zstd::encode_all(std::io::Cursor::new(&tar_data), 3).unwrap()
}

/// Write bytes to a temp file and return it.
fn write_temp(data: &[u8]) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(data).unwrap();
    f.flush().unwrap();
    f
}

/// Drive indexing engine with in-memory data.
fn index_in_memory(data: &[u8], format: CompressionFormat) -> ArchiveIndex {
    let mut engine =
        IndexingEngine::new(format, None, DEFAULT_CHECKPOINT_INTERVAL, data.len() as u64).unwrap();
    let mut offset = 0;
    let chunk_size = 8192;

    loop {
        match engine.step() {
            EngineRequest::NeedInput => {
                if offset >= data.len() {
                    engine.signal_eof();
                } else {
                    let end = (offset + chunk_size).min(data.len());
                    engine.provide_data(&data[offset..end]);
                    offset = end;
                }
            }
            EngineRequest::Done => break,
            EngineRequest::Error(e) => panic!("indexing error: {}", e),
            _ => {}
        }
    }

    engine.finish()
}

/// Read a file using read engine with in-memory data.
fn read_in_memory(data: &[u8], index: &ArchiveIndex, path: &str) -> Vec<u8> {
    let mut engine = ReadEngine::new(index, path).unwrap();
    let mut result = Vec::new();
    let mut offset = 0;
    let chunk_size = 8192;

    loop {
        match engine.step() {
            EngineRequest::NeedInput => {
                if offset >= data.len() {
                    engine.signal_eof();
                } else {
                    let end = (offset + chunk_size).min(data.len());
                    engine.provide_data(&data[offset..end]);
                    offset = end;
                }
            }
            EngineRequest::SeekAndRead { offset: off, len } => {
                let start = off as usize;
                let end = (start + len).min(data.len());
                if start >= data.len() {
                    engine.signal_eof();
                } else {
                    engine.provide_data(&data[start..end]);
                    offset = end;
                }
            }
            EngineRequest::OutputReady => {
                let mut buf = vec![0u8; 65536];
                loop {
                    let n = engine.read_output(&mut buf);
                    if n == 0 {
                        break;
                    }
                    result.extend_from_slice(&buf[..n]);
                }
            }
            EngineRequest::Done => break,
            EngineRequest::Error(e) => panic!("read error: {}", e),
        }
    }

    result
}

/// Read a byte range from a file using read engine with in-memory data.
fn read_range_in_memory(
    data: &[u8],
    index: &ArchiveIndex,
    path: &str,
    file_offset: u64,
    len: u64,
) -> Vec<u8> {
    let mut engine = ReadEngine::new_range(index, path, file_offset, len).unwrap();
    let mut result = Vec::new();
    let mut offset = 0;
    let chunk_size = 8192;

    loop {
        match engine.step() {
            EngineRequest::NeedInput => {
                if offset >= data.len() {
                    engine.signal_eof();
                } else {
                    let end = (offset + chunk_size).min(data.len());
                    engine.provide_data(&data[offset..end]);
                    offset = end;
                }
            }
            EngineRequest::SeekAndRead { offset: off, len } => {
                let start = off as usize;
                let end = (start + len).min(data.len());
                if start >= data.len() {
                    engine.signal_eof();
                } else {
                    engine.provide_data(&data[start..end]);
                    offset = end;
                }
            }
            EngineRequest::OutputReady => {
                let mut buf = vec![0u8; 65536];
                loop {
                    let n = engine.read_output(&mut buf);
                    if n == 0 {
                        break;
                    }
                    result.extend_from_slice(&buf[..n]);
                }
            }
            EngineRequest::Done => break,
            EngineRequest::Error(e) => panic!("range read error: {}", e),
        }
    }

    result
}

// ─── Test Files ───

fn test_files() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("hello.txt", b"Hello, world!".to_vec()),
        ("data.bin", (0..1000).map(|i| (i % 256) as u8).collect()),
        ("empty.txt", Vec::new()),
        (
            "subdir/nested.txt",
            b"This is a nested file.".to_vec(),
        ),
        (
            "large.txt",
            (0..50000)
                .map(|i| b"abcdefghij\n"[i % 11])
                .collect(),
        ),
    ]
}

fn test_files_refs<'a>(files: &'a [(&'a str, Vec<u8>)]) -> Vec<(&'a str, &'a [u8])> {
    files.iter().map(|(p, d)| (*p, d.as_slice())).collect()
}

// ─── Uncompressed Tar Tests ───

#[test]
fn test_uncompressed_index_and_read() {
    let files = test_files();
    let refs = test_files_refs(&files);
    let tar_data = create_tar_bytes(&refs);

    let index = index_in_memory(&tar_data, CompressionFormat::None);
    assert_eq!(index.entries.len(), files.len());

    for (path, expected) in &files {
        let entry = index.get(path).unwrap();
        assert_eq!(entry.size, expected.len() as u64, "size mismatch for {}", path);

        let content = read_in_memory(&tar_data, &index, path);
        assert_eq!(&content, expected, "content mismatch for {}", path);
    }
}

// ─── Gzip Tests ───

#[test]
fn test_gzip_index_and_read() {
    let files = test_files();
    let refs = test_files_refs(&files);
    let compressed = create_tar_gz(&refs);

    let index = index_in_memory(&compressed, CompressionFormat::Gzip);
    assert_eq!(index.entries.len(), files.len());

    for (path, expected) in &files {
        let entry = index.get(path).unwrap();
        assert_eq!(entry.size, expected.len() as u64, "size mismatch for {}", path);

        let content = read_in_memory(&compressed, &index, path);
        assert_eq!(&content, expected, "content mismatch for {}", path);
    }
}

// ─── Bzip2 Tests ───

#[test]
fn test_bzip2_index_and_read() {
    let files = test_files();
    let refs = test_files_refs(&files);
    let compressed = create_tar_bz2(&refs);

    let index = index_in_memory(&compressed, CompressionFormat::Bzip2);
    assert_eq!(index.entries.len(), files.len());

    for (path, expected) in &files {
        let entry = index.get(path).unwrap();
        assert_eq!(entry.size, expected.len() as u64, "size mismatch for {}", path);

        let content = read_in_memory(&compressed, &index, path);
        assert_eq!(&content, expected, "content mismatch for {}", path);
    }
}

// ─── XZ Tests ───

#[test]
fn test_xz_index_and_read() {
    let files = test_files();
    let refs = test_files_refs(&files);
    let compressed = create_tar_xz(&refs);

    let index = index_in_memory(&compressed, CompressionFormat::Xz);
    assert_eq!(index.entries.len(), files.len());

    for (path, expected) in &files {
        let entry = index.get(path).unwrap();
        assert_eq!(entry.size, expected.len() as u64, "size mismatch for {}", path);

        let content = read_in_memory(&compressed, &index, path);
        assert_eq!(&content, expected, "content mismatch for {}", path);
    }
}

// ─── Zstd Tests ───

#[test]
fn test_zstd_index_and_read() {
    let files = test_files();
    let refs = test_files_refs(&files);
    let compressed = create_tar_zst(&refs);

    let index = index_in_memory(&compressed, CompressionFormat::Zstd);
    assert_eq!(index.entries.len(), files.len());

    for (path, expected) in &files {
        let entry = index.get(path).unwrap();
        assert_eq!(entry.size, expected.len() as u64, "size mismatch for {}", path);

        let content = read_in_memory(&compressed, &index, path);
        assert_eq!(&content, expected, "content mismatch for {}", path);
    }
}

// ─── SyncArchive Tests ───

#[test]
fn test_sync_archive_gzip() {
    let files = test_files();
    let refs = test_files_refs(&files);
    let compressed = create_tar_gz(&refs);
    let tmp = write_temp(&compressed);

    let archive = SyncArchive::open(tmp.path()).unwrap();
    assert_eq!(archive.list().len(), files.len());

    for (path, expected) in &files {
        let content = archive.read_file(path).unwrap();
        assert_eq!(&content, expected, "content mismatch for {}", path);
    }
}

#[test]
fn test_sync_archive_bzip2() {
    let files = test_files();
    let refs = test_files_refs(&files);
    let compressed = create_tar_bz2(&refs);
    let tmp = write_temp(&compressed);

    let archive = SyncArchive::open(tmp.path()).unwrap();
    assert_eq!(archive.list().len(), files.len());

    for (path, expected) in &files {
        let content = archive.read_file(path).unwrap();
        assert_eq!(&content, expected, "content mismatch for {}", path);
    }
}

#[test]
fn test_sync_archive_xz() {
    let files = test_files();
    let refs = test_files_refs(&files);
    let compressed = create_tar_xz(&refs);
    let tmp = write_temp(&compressed);

    let archive = SyncArchive::open(tmp.path()).unwrap();
    assert_eq!(archive.list().len(), files.len());

    for (path, expected) in &files {
        let content = archive.read_file(path).unwrap();
        assert_eq!(&content, expected, "content mismatch for {}", path);
    }
}

#[test]
fn test_sync_archive_zstd() {
    let files = test_files();
    let refs = test_files_refs(&files);
    let compressed = create_tar_zst(&refs);
    let tmp = write_temp(&compressed);

    let archive = SyncArchive::open(tmp.path()).unwrap();
    assert_eq!(archive.list().len(), files.len());

    for (path, expected) in &files {
        let content = archive.read_file(path).unwrap();
        assert_eq!(&content, expected, "content mismatch for {}", path);
    }
}

#[test]
fn test_sync_archive_uncompressed() {
    let files = test_files();
    let refs = test_files_refs(&files);
    let tar_data = create_tar_bytes(&refs);
    let tmp = write_temp(&tar_data);

    let archive = SyncArchive::open(tmp.path()).unwrap();
    assert_eq!(archive.list().len(), files.len());

    for (path, expected) in &files {
        let content = archive.read_file(path).unwrap();
        assert_eq!(&content, expected, "content mismatch for {}", path);
    }
}

// ─── Index Persistence Tests ───

#[test]
fn test_index_save_and_load() {
    let files = test_files();
    let refs = test_files_refs(&files);
    let compressed = create_tar_gz(&refs);
    let tmp = write_temp(&compressed);

    let archive = SyncArchive::open(tmp.path()).unwrap();

    // Save index
    let index_file = NamedTempFile::new().unwrap();
    archive.save_index(index_file.path()).unwrap();

    // Load index
    let loaded_index = SyncArchive::load_index(index_file.path()).unwrap();

    assert_eq!(loaded_index.entries.len(), files.len());
    for (path, expected) in &files {
        let entry = loaded_index.get(path).unwrap();
        assert_eq!(entry.size, expected.len() as u64);
    }

    // Use loaded index to read files
    let archive2 = SyncArchive::open_with_index(tmp.path(), loaded_index);
    for (path, expected) in &files {
        let content = archive2.read_file(path).unwrap();
        assert_eq!(&content, expected, "content mismatch for {}", path);
    }
}

// ─── Checkpoint Tests ───

#[test]
fn test_checkpoints_created() {
    let files = test_files();
    let refs = test_files_refs(&files);
    let compressed = create_tar_gz(&refs);

    // Use small checkpoint interval to force multiple checkpoints
    let index = {
        let mut engine =
            IndexingEngine::new(CompressionFormat::Gzip, None, 1024, compressed.len() as u64)
                .unwrap();
        let mut offset = 0;
        loop {
            match engine.step() {
                EngineRequest::NeedInput => {
                    if offset >= compressed.len() {
                        engine.signal_eof();
                    } else {
                        let end = (offset + 4096).min(compressed.len());
                        engine.provide_data(&compressed[offset..end]);
                        offset = end;
                    }
                }
                EngineRequest::Done => break,
                EngineRequest::Error(e) => panic!("error: {}", e),
                _ => {}
            }
        }
        engine.finish()
    };

    // Should have multiple checkpoints due to small interval
    assert!(
        index.checkpoints.len() > 1,
        "expected multiple checkpoints, got {}",
        index.checkpoints.len()
    );

    // Checkpoints should be sorted by uncompressed offset
    for pair in index.checkpoints.windows(2) {
        assert!(pair[0].uncompressed_offset <= pair[1].uncompressed_offset);
    }

    // Should still be able to read files correctly
    for (path, expected) in &files {
        let content = read_in_memory(&compressed, &index, path);
        assert_eq!(&content, expected, "content mismatch for {}", path);
    }
}

#[test]
fn test_checkpoint_with_sync_archive() {
    let files = test_files();
    let refs = test_files_refs(&files);
    let compressed = create_tar_gz(&refs);
    let tmp = write_temp(&compressed);

    // Small checkpoint interval
    let archive = SyncArchive::open_with_interval(tmp.path(), 1024).unwrap();

    assert!(archive.index().checkpoints.len() > 1);

    for (path, expected) in &files {
        let content = archive.read_file(path).unwrap();
        assert_eq!(&content, expected, "content mismatch for {}", path);
    }
}

// ─── Edge Cases ───

#[test]
fn test_empty_archive() {
    // An archive with no files (just two zero blocks)
    let tar_data = create_tar_bytes(&[]);
    let tmp = write_temp(&tar_data);

    let archive = SyncArchive::open(tmp.path()).unwrap();
    assert_eq!(archive.list().len(), 0);
}

#[test]
fn test_single_file_archive() {
    let compressed = create_tar_gz(&[("only.txt", b"only file")]);
    let tmp = write_temp(&compressed);

    let archive = SyncArchive::open(tmp.path()).unwrap();
    assert_eq!(archive.list().len(), 1);
    assert_eq!(archive.read_file("only.txt").unwrap(), b"only file");
}

#[test]
fn test_file_not_found() {
    let compressed = create_tar_gz(&[("exists.txt", b"data")]);
    let tmp = write_temp(&compressed);

    let archive = SyncArchive::open(tmp.path()).unwrap();
    let result = archive.read_file("nonexistent.txt");
    assert!(result.is_err());
}

#[test]
fn test_large_file_in_archive() {
    // 500 KB file
    let large_content: Vec<u8> = (0..500_000).map(|i| (i % 256) as u8).collect();
    let compressed = create_tar_gz(&[("large.bin", &large_content)]);
    let tmp = write_temp(&compressed);

    let archive = SyncArchive::open(tmp.path()).unwrap();
    let content = archive.read_file("large.bin").unwrap();
    assert_eq!(content, large_content);
}

#[test]
fn test_many_files() {
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    for i in 0..100 {
        files.push((format!("file_{:03}.txt", i), format!("content of file {}", i).into_bytes()));
    }
    let refs: Vec<(&str, &[u8])> = files.iter().map(|(p, d)| (p.as_str(), d.as_slice())).collect();
    let compressed = create_tar_gz(&refs);
    let tmp = write_temp(&compressed);

    let archive = SyncArchive::open(tmp.path()).unwrap();
    assert_eq!(archive.list().len(), 100);

    for (path, expected) in &files {
        let content = archive.read_file(path).unwrap();
        assert_eq!(&content, expected, "mismatch for {}", path);
    }
}

// ─── Format Detection Tests ───

#[test]
fn test_auto_detect_gzip() {
    let compressed = create_tar_gz(&[("test.txt", b"hello")]);
    let tmp = write_temp(&compressed);

    let archive = SyncArchive::open(tmp.path()).unwrap();
    assert_eq!(
        archive.index().metadata.compression,
        CompressionFormat::Gzip
    );
}

#[test]
fn test_auto_detect_bzip2() {
    let compressed = create_tar_bz2(&[("test.txt", b"hello")]);
    let tmp = write_temp(&compressed);

    let archive = SyncArchive::open(tmp.path()).unwrap();
    assert_eq!(
        archive.index().metadata.compression,
        CompressionFormat::Bzip2
    );
}

#[test]
fn test_auto_detect_xz() {
    let compressed = create_tar_xz(&[("test.txt", b"hello")]);
    let tmp = write_temp(&compressed);

    let archive = SyncArchive::open(tmp.path()).unwrap();
    assert_eq!(
        archive.index().metadata.compression,
        CompressionFormat::Xz
    );
}

#[test]
fn test_auto_detect_zstd() {
    let compressed = create_tar_zst(&[("test.txt", b"hello")]);
    let tmp = write_temp(&compressed);

    let archive = SyncArchive::open(tmp.path()).unwrap();
    assert_eq!(
        archive.index().metadata.compression,
        CompressionFormat::Zstd
    );
}

// ─── Gzip Checkpoint Seek Test ───

#[test]
fn test_gzip_checkpoint_midstream_seek() {
    // Use pseudo-random data that doesn't compress well, forcing the
    // deflate encoder to emit multiple blocks. Highly compressible data
    // may fit in a single deflate block, producing no block boundaries.
    let mut rng: u64 = 42;
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    for i in 0..20 {
        let content: Vec<u8> = (0..20_000)
            .map(|_| {
                rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
                (rng >> 33) as u8
            })
            .collect();
        files.push((format!("file_{:03}.dat", i), content));
    }
    let refs: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(p, d)| (p.as_str(), d.as_slice()))
        .collect();
    let compressed = create_tar_gz(&refs);

    // Use a checkpoint interval of 64KB
    let index = {
        let mut engine =
            IndexingEngine::new(CompressionFormat::Gzip, None, 65536, compressed.len() as u64).unwrap();
        let mut offset = 0;
        loop {
            match engine.step() {
                EngineRequest::NeedInput => {
                    if offset >= compressed.len() {
                        engine.signal_eof();
                    } else {
                        let end = (offset + 8192).min(compressed.len());
                        engine.provide_data(&compressed[offset..end]);
                        offset = end;
                    }
                }
                EngineRequest::Done => break,
                EngineRequest::Error(e) => panic!("indexing error: {}", e),
                _ => {}
            }
        }
        engine.finish()
    };

    // Should have multiple checkpoints (initial + block boundary checkpoints)
    assert!(
        index.checkpoints.len() > 2,
        "expected multiple checkpoints, got {}",
        index.checkpoints.len()
    );

    // At least one checkpoint should have compressed_offset > 0
    // (proving mid-stream resume, not restart from beginning)
    let midstream_checkpoints: Vec<_> = index
        .checkpoints
        .iter()
        .filter(|cp| cp.compressed_offset > 0)
        .collect();
    assert!(
        !midstream_checkpoints.is_empty(),
        "expected at least one mid-stream checkpoint"
    );

    // Verify all files can be read correctly using the index
    for (path, expected) in &files {
        let content = read_in_memory(&compressed, &index, path);
        assert_eq!(&content, expected, "content mismatch for {}", path);
    }

    // Verify a file near the end uses a checkpoint with offset > 0
    let last_file = "file_019.dat";
    let entry = index.get(last_file).unwrap();
    let cp = &index.checkpoints[entry.checkpoint_index];
    assert!(
        cp.compressed_offset > 0,
        "last file's checkpoint should have compressed_offset > 0, \
         checkpoint_index={}, compressed_offset={}",
        entry.checkpoint_index,
        cp.compressed_offset
    );
}

// ─── Index Query Tests ───

#[test]
fn test_list_directory() {
    let files = &[
        ("root.txt", &b"root"[..]),
        ("dir/a.txt", &b"a"[..]),
        ("dir/b.txt", &b"b"[..]),
        ("other/c.txt", &b"c"[..]),
    ];
    let compressed = create_tar_gz(files);
    let index = index_in_memory(&compressed, CompressionFormat::Gzip);

    let dir_entries = index.list(Some("dir"));
    assert_eq!(dir_entries.len(), 2);

    let all_entries = index.list(None);
    assert_eq!(all_entries.len(), 4);
}

// ─── Index Serialization Roundtrip ───

#[test]
fn test_index_bytes_roundtrip() {
    let files = test_files();
    let refs = test_files_refs(&files);
    let compressed = create_tar_gz(&refs);

    let index = index_in_memory(&compressed, CompressionFormat::Gzip);
    let bytes = index.to_bytes().unwrap();
    let restored = ArchiveIndex::from_bytes(&bytes).unwrap();

    assert_eq!(restored.entries.len(), index.entries.len());
    assert_eq!(restored.checkpoints.len(), index.checkpoints.len());
    assert_eq!(restored.metadata.compression, index.metadata.compression);

    for (path, _) in &files {
        let orig = index.get(path).unwrap();
        let rest = restored.get(path).unwrap();
        assert_eq!(orig.size, rest.size);
        assert_eq!(orig.uncompressed_offset, rest.uncompressed_offset);
        assert_eq!(orig.checkpoint_index, rest.checkpoint_index);
    }
}

// ─── Incremental Indexing Tests ───

#[test]
fn test_progress_tracking() {
    let files = test_files();
    let refs = test_files_refs(&files);
    let compressed = create_tar_gz(&refs);

    let mut engine =
        IndexingEngine::new(CompressionFormat::Gzip, None, DEFAULT_CHECKPOINT_INTERVAL, compressed.len() as u64)
            .unwrap();

    let initial = engine.progress();
    assert_eq!(initial.compressed_bytes_processed, 0);
    assert_eq!(initial.entries_found, 0);
    assert!(!initial.is_complete);
    assert_eq!(initial.compressed_bytes_total, compressed.len() as u64);

    let mut offset = 0;
    loop {
        match engine.step() {
            EngineRequest::NeedInput => {
                if offset >= compressed.len() {
                    engine.signal_eof();
                } else {
                    let end = (offset + 4096).min(compressed.len());
                    engine.provide_data(&compressed[offset..end]);
                    offset = end;
                }
            }
            EngineRequest::Done => break,
            EngineRequest::Error(e) => panic!("error: {}", e),
            _ => {}
        }
    }

    let final_progress = engine.progress();
    assert!(final_progress.is_complete);
    assert_eq!(final_progress.entries_found, files.len());
    assert!(final_progress.compressed_bytes_processed > 0);
    assert!(final_progress.uncompressed_bytes_processed > 0);
    assert!(final_progress.last_entry_path.is_some());
    assert!(final_progress.fraction().unwrap() > 0.0);
}

#[test]
fn test_snapshot_index_usable_for_reads() {
    // Use larger files so indexing spans many provide_data calls
    let files: Vec<(&str, Vec<u8>)> = (0..20)
        .map(|i| {
            let name: &str = Box::leak(format!("file_{:02}.txt", i).into_boxed_str());
            let content: Vec<u8> = vec![(i * 7 + 3) as u8; 10_000];
            (name, content)
        })
        .collect();
    let refs: Vec<(&str, &[u8])> = files.iter().map(|(p, d)| (*p, d.as_slice())).collect();
    let compressed = create_tar_gz(&refs);

    let mut engine =
        IndexingEngine::new(CompressionFormat::Gzip, None, DEFAULT_CHECKPOINT_INTERVAL, compressed.len() as u64)
            .unwrap();

    let mut offset = 0;
    let mut snapshot = None;
    let chunk_size = 512; // small chunks for fine-grained progress

    loop {
        match engine.step() {
            EngineRequest::NeedInput => {
                if offset >= compressed.len() {
                    engine.signal_eof();
                } else {
                    let end = (offset + chunk_size).min(compressed.len());
                    engine.provide_data(&compressed[offset..end]);
                    offset = end;
                }
            }
            EngineRequest::Done => break,
            EngineRequest::Error(e) => panic!("error: {}", e),
            _ => {}
        }

        // Take a snapshot once we have some entries
        let p = engine.progress();
        if p.entries_found >= 3 && snapshot.is_none() {
            snapshot = Some(engine.snapshot_index());
        }
    }

    let snap = snapshot.expect("should have taken a snapshot");
    assert!(!snap.metadata.complete);
    assert!(snap.entries.len() >= 3);

    // Verify we can read files from the snapshot
    for (path, expected) in &files {
        if let Some(_entry) = snap.get(path) {
            let content = read_in_memory(&compressed, &snap, path);
            assert_eq!(&content, expected, "snapshot read mismatch for {}", path);
        }
    }

    // Final index should be complete and have all entries
    let final_index = engine.finish();
    assert!(final_index.metadata.complete);
    assert_eq!(final_index.entries.len(), files.len());
}

#[test]
fn test_cancel_returns_partial_index() {
    // Use larger files so indexing spans many provide_data calls
    let files: Vec<(&str, Vec<u8>)> = (0..30)
        .map(|i| {
            let name: &str = Box::leak(format!("item_{:03}.dat", i).into_boxed_str());
            let content: Vec<u8> = vec![i as u8; 10_000];
            (name, content)
        })
        .collect();
    let refs: Vec<(&str, &[u8])> = files.iter().map(|(p, d)| (*p, d.as_slice())).collect();
    let compressed = create_tar_gz(&refs);

    let mut engine =
        IndexingEngine::new(CompressionFormat::Gzip, None, DEFAULT_CHECKPOINT_INTERVAL, compressed.len() as u64)
            .unwrap();

    let mut offset = 0;
    let chunk_size = 512; // small chunks for fine-grained progress
    loop {
        match engine.step() {
            EngineRequest::NeedInput => {
                if offset >= compressed.len() {
                    engine.signal_eof();
                } else {
                    let end = (offset + chunk_size).min(compressed.len());
                    engine.provide_data(&compressed[offset..end]);
                    offset = end;
                }
            }
            EngineRequest::Done => panic!("should have cancelled before done"),
            EngineRequest::Error(e) => panic!("error: {}", e),
            _ => {}
        }

        if engine.progress().entries_found >= 5 {
            break;
        }
    }

    let partial = engine.cancel();
    assert!(!partial.metadata.complete);
    assert!(partial.entries.len() >= 5);
    assert!(partial.entries.len() < files.len());

    // Files in the partial index should be readable
    for (path, expected) in &files {
        if let Some(_entry) = partial.get(path) {
            let content = read_in_memory(&compressed, &partial, path);
            assert_eq!(&content, expected, "partial read mismatch for {}", path);
        }
    }
}

#[test]
fn test_partial_index_serialization_roundtrip() {
    let files = test_files();
    let refs = test_files_refs(&files);
    let compressed = create_tar_gz(&refs);

    let mut engine =
        IndexingEngine::new(CompressionFormat::Gzip, None, DEFAULT_CHECKPOINT_INTERVAL, compressed.len() as u64)
            .unwrap();

    // Run partway then cancel
    let mut offset = 0;
    loop {
        match engine.step() {
            EngineRequest::NeedInput => {
                if offset >= compressed.len() {
                    engine.signal_eof();
                } else {
                    let end = (offset + 4096).min(compressed.len());
                    engine.provide_data(&compressed[offset..end]);
                    offset = end;
                }
            }
            EngineRequest::Done => break,
            EngineRequest::Error(e) => panic!("error: {}", e),
            _ => {}
        }
    }

    let index = engine.finish();
    assert!(index.metadata.complete);

    // Serialize and deserialize — complete field should survive
    let bytes = index.to_bytes().unwrap();
    let restored = ArchiveIndex::from_bytes(&bytes).unwrap();
    assert!(restored.metadata.complete);
}

// ─── Range Read Tests ───

#[test]
fn test_range_read_first_bytes() {
    let content: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();
    let files = &[("big.bin", content.as_slice())];
    let compressed = create_tar_gz(files);
    let index = index_in_memory(&compressed, CompressionFormat::Gzip);

    // Read first 100 bytes
    let range = read_range_in_memory(&compressed, &index, "big.bin", 0, 100);
    assert_eq!(range.len(), 100);
    assert_eq!(&range, &content[..100]);
}

#[test]
fn test_range_read_middle() {
    let content: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();
    let files = &[("big.bin", content.as_slice())];
    let compressed = create_tar_gz(files);
    let index = index_in_memory(&compressed, CompressionFormat::Gzip);

    // Read 200 bytes from the middle
    let range = read_range_in_memory(&compressed, &index, "big.bin", 2000, 200);
    assert_eq!(range.len(), 200);
    assert_eq!(&range, &content[2000..2200]);
}

#[test]
fn test_range_read_end() {
    let content: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();
    let files = &[("big.bin", content.as_slice())];
    let compressed = create_tar_gz(files);
    let index = index_in_memory(&compressed, CompressionFormat::Gzip);

    // Read last 50 bytes
    let range = read_range_in_memory(&compressed, &index, "big.bin", 4950, 50);
    assert_eq!(range.len(), 50);
    assert_eq!(&range, &content[4950..5000]);
}

#[test]
fn test_range_read_past_end_clamps() {
    let content: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
    let files = &[("small.bin", content.as_slice())];
    let compressed = create_tar_gz(files);
    let index = index_in_memory(&compressed, CompressionFormat::Gzip);

    // Offset past end — should return empty
    let range = read_range_in_memory(&compressed, &index, "small.bin", 2000, 100);
    assert!(range.is_empty());

    // Offset within, but len extends past end — should clamp
    let range = read_range_in_memory(&compressed, &index, "small.bin", 900, 500);
    assert_eq!(range.len(), 100);
    assert_eq!(&range, &content[900..1000]);
}

#[test]
fn test_range_read_entire_file() {
    let content: Vec<u8> = (0..3000).map(|i| (i % 256) as u8).collect();
    let files = &[("data.bin", content.as_slice())];
    let compressed = create_tar_gz(files);
    let index = index_in_memory(&compressed, CompressionFormat::Gzip);

    // Range covering the entire file should match full read
    let range = read_range_in_memory(&compressed, &index, "data.bin", 0, 3000);
    let full = read_in_memory(&compressed, &index, "data.bin");
    assert_eq!(range, full);
}

#[test]
fn test_range_read_zero_length() {
    let content = b"hello world";
    let files = &[("file.txt", &content[..])];
    let compressed = create_tar_gz(files);
    let index = index_in_memory(&compressed, CompressionFormat::Gzip);

    let range = read_range_in_memory(&compressed, &index, "file.txt", 5, 0);
    assert!(range.is_empty());
}

#[test]
fn test_range_read_across_checkpoints() {
    // Create a large file that will span multiple checkpoints
    let content: Vec<u8> = (0..200_000).map(|i| (i % 256) as u8).collect();
    let files = &[("large.bin", content.as_slice())];
    let compressed = create_tar_gz(files);

    // Use a small checkpoint interval to force multiple checkpoints
    let index = {
        let mut engine =
            IndexingEngine::new(CompressionFormat::Gzip, None, 32 * 1024, compressed.len() as u64)
                .unwrap();
        let mut offset = 0;
        loop {
            match engine.step() {
                EngineRequest::NeedInput => {
                    if offset >= compressed.len() {
                        engine.signal_eof();
                    } else {
                        let end = (offset + 8192).min(compressed.len());
                        engine.provide_data(&compressed[offset..end]);
                        offset = end;
                    }
                }
                EngineRequest::Done => break,
                EngineRequest::Error(e) => panic!("error: {}", e),
                _ => {}
            }
        }
        engine.finish()
    };

    assert!(
        index.checkpoints.len() > 2,
        "expected multiple checkpoints for range test, got {}",
        index.checkpoints.len()
    );

    // Read from the second half — should use a checkpoint past the beginning
    let range = read_range_in_memory(&compressed, &index, "large.bin", 150_000, 1000);
    assert_eq!(range.len(), 1000);
    assert_eq!(&range, &content[150_000..151_000]);

    // Verify it picks a checkpoint in the second half
    let entry = index.get("large.bin").unwrap();
    let target_offset = entry.uncompressed_offset + 150_000;
    let (cp_idx, _) = index.best_checkpoint_for_offset(target_offset);
    assert!(cp_idx > 0, "should use a mid-stream checkpoint");
}

#[test]
fn test_range_read_all_formats() {
    let content: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();

    let formats: Vec<(CompressionFormat, Vec<u8>)> = vec![
        (CompressionFormat::Gzip, create_tar_gz(&[("f.bin", content.as_slice())])),
        (CompressionFormat::Bzip2, create_tar_bz2(&[("f.bin", content.as_slice())])),
        (CompressionFormat::Xz, create_tar_xz(&[("f.bin", content.as_slice())])),
        (CompressionFormat::Zstd, create_tar_zst(&[("f.bin", content.as_slice())])),
        (CompressionFormat::None, create_tar_bytes(&[("f.bin", content.as_slice())])),
    ];

    for (format, compressed) in &formats {
        let index = index_in_memory(compressed, *format);

        let range = read_range_in_memory(compressed, &index, "f.bin", 1000, 500);
        assert_eq!(
            range.len(),
            500,
            "range len mismatch for {:?}",
            format
        );
        assert_eq!(
            &range,
            &content[1000..1500],
            "range content mismatch for {:?}",
            format
        );
    }
}

#[test]
fn test_sync_archive_range_read() {
    let content: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
    let compressed = create_tar_gz(&[("data.bin", content.as_slice())]);
    let tmp = write_temp(&compressed);

    let archive = SyncArchive::open(tmp.path()).unwrap();

    // Read a range
    let range = archive.read_file_range("data.bin", 5000, 2000).unwrap();
    assert_eq!(range.len(), 2000);
    assert_eq!(&range, &content[5000..7000]);

    // Offset past end
    let range = archive.read_file_range("data.bin", 20_000, 100).unwrap();
    assert!(range.is_empty());

    // Full file via range should match read_file
    let full_range = archive.read_file_range("data.bin", 0, 10_000).unwrap();
    let full = archive.read_file("data.bin").unwrap();
    assert_eq!(full_range, full);
}

// ─── CPIO Helpers ───

/// Create a newc-format cpio archive in memory.
fn create_cpio_bytes(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut archive = Vec::new();
    let mut ino = 1u64;

    for (path, content) in files {
        let namesize = path.len() + 1; // include null terminator
        let filesize = content.len();

        let header = format!(
            "070701\
             {:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}\
             {:08X}{:08X}{:08X}{:08X}{:08X}{:08X}",
            ino,
            0o100644u32, // mode: regular file
            1000u32, 1000u32, 1u32, 1700000000u32, filesize,
            0u32, 0u32, 0u32, 0u32, namesize, 0u32,
        );
        archive.extend_from_slice(header.as_bytes());
        archive.extend_from_slice(path.as_bytes());
        archive.push(0);

        // Pad header+name to 4-byte boundary
        let total = 110 + namesize;
        let padded = (total + 3) & !3;
        archive.resize(archive.len() + padded - total, 0);

        // Write data
        archive.extend_from_slice(content);
        let data_padded = (filesize + 3) & !3;
        archive.resize(archive.len() + data_padded - filesize, 0);

        ino += 1;
    }

    // Trailer
    let trailer = "TRAILER!!!";
    let namesize = trailer.len() + 1;
    let header = format!(
        "070701\
         {:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}\
         {:08X}{:08X}{:08X}{:08X}{:08X}{:08X}",
        0u32, 0u32, 0u32, 0u32, 1u32, 0u32, 0u32,
        0u32, 0u32, 0u32, 0u32, namesize, 0u32,
    );
    archive.extend_from_slice(header.as_bytes());
    archive.extend_from_slice(trailer.as_bytes());
    archive.push(0);
    let total = 110 + namesize;
    let padded = (total + 3) & !3;
    archive.resize(archive.len() + padded - total, 0);

    archive
}

/// Create a gzip-compressed cpio archive.
fn create_cpio_gz(files: &[(&str, &[u8])]) -> Vec<u8> {
    let cpio_data = create_cpio_bytes(files);
    let mut encoder =
        flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&cpio_data).unwrap();
    encoder.finish().unwrap()
}

// ─── CPIO Tests ───

#[test]
fn test_cpio_index_and_read() {
    let files: Vec<(&str, Vec<u8>)> = vec![
        ("hello.txt", b"Hello, world!".to_vec()),
        ("data.bin", (0..1000).map(|i| (i % 256) as u8).collect()),
    ];
    let refs: Vec<(&str, &[u8])> = files.iter().map(|(p, d)| (*p, d.as_slice())).collect();
    let cpio_data = create_cpio_bytes(&refs);

    let index = index_in_memory(&cpio_data, CompressionFormat::None);

    assert_eq!(index.entries.len(), 2);
    assert!(index.get("hello.txt").is_some());
    assert!(index.get("data.bin").is_some());
    assert_eq!(index.get("hello.txt").unwrap().size, 13);
    assert_eq!(index.metadata.archive_format, ArchiveFormat::Cpio);

    // Read back contents
    let content1 = read_in_memory(&cpio_data, &index, "hello.txt");
    assert_eq!(&content1, b"Hello, world!");

    let content2 = read_in_memory(&cpio_data, &index, "data.bin");
    assert_eq!(content2.len(), 1000);
    for (i, &byte) in content2.iter().enumerate() {
        assert_eq!(byte, (i % 256) as u8, "mismatch at byte {}", i);
    }
}

#[test]
fn test_cpio_gzip_index_and_read() {
    let files = &[
        ("file1.txt", &b"First file content"[..]),
        ("file2.txt", &b"Second file content"[..]),
    ];
    let compressed = create_cpio_gz(files);

    let index = index_in_memory(&compressed, CompressionFormat::Gzip);

    assert_eq!(index.entries.len(), 2);
    assert_eq!(index.metadata.archive_format, ArchiveFormat::Cpio);

    let content1 = read_in_memory(&compressed, &index, "file1.txt");
    assert_eq!(&content1, b"First file content");

    let content2 = read_in_memory(&compressed, &index, "file2.txt");
    assert_eq!(&content2, b"Second file content");
}

#[test]
fn test_cpio_auto_detect() {
    let tar_data = create_tar_bytes(&[("tar_file.txt", &b"from tar"[..])]);
    let cpio_data = create_cpio_bytes(&[("cpio_file.txt", &b"from cpio"[..])]);

    let tar_index = index_in_memory(&tar_data, CompressionFormat::None);
    assert_eq!(tar_index.metadata.archive_format, ArchiveFormat::Tar);
    assert!(tar_index.get("tar_file.txt").is_some());

    let cpio_index = index_in_memory(&cpio_data, CompressionFormat::None);
    assert_eq!(cpio_index.metadata.archive_format, ArchiveFormat::Cpio);
    assert!(cpio_index.get("cpio_file.txt").is_some());
}

#[test]
fn test_cpio_many_files() {
    let files: Vec<(&str, Vec<u8>)> = (0..50)
        .map(|i| {
            let name: &str = Box::leak(format!("file_{:03}.dat", i).into_boxed_str());
            let content: Vec<u8> = vec![(i * 7 + 13) as u8; 500];
            (name, content)
        })
        .collect();
    let refs: Vec<(&str, &[u8])> = files.iter().map(|(p, d)| (*p, d.as_slice())).collect();
    let cpio_data = create_cpio_bytes(&refs);

    let index = index_in_memory(&cpio_data, CompressionFormat::None);
    assert_eq!(index.entries.len(), 50);

    for (path, expected) in &files {
        let content = read_in_memory(&cpio_data, &index, path);
        assert_eq!(&content, expected, "content mismatch for {}", path);
    }
}

#[test]
fn test_cpio_range_read() {
    let content: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();
    let cpio_data = create_cpio_bytes(&[("big.bin", content.as_slice())]);

    let index = index_in_memory(&cpio_data, CompressionFormat::None);

    let range = read_range_in_memory(&cpio_data, &index, "big.bin", 1000, 500);
    assert_eq!(range.len(), 500);
    assert_eq!(&range, &content[1000..1500]);
}

#[test]
fn test_cpio_sync_archive() {
    let files = &[
        ("a.txt", &b"alpha"[..]),
        ("b.txt", &b"beta"[..]),
        ("c.txt", &b"gamma"[..]),
    ];
    let compressed = create_cpio_gz(files);
    let tmp = write_temp(&compressed);

    let archive = SyncArchive::open(tmp.path()).unwrap();

    let entries = archive.list();
    assert_eq!(entries.len(), 3);

    assert_eq!(archive.read_file("a.txt").unwrap(), b"alpha");
    assert_eq!(archive.read_file("b.txt").unwrap(), b"beta");
    assert_eq!(archive.read_file("c.txt").unwrap(), b"gamma");
}

#[test]
fn test_cpio_empty_file() {
    let cpio_data = create_cpio_bytes(&[("empty.txt", &b""[..])]);
    let index = index_in_memory(&cpio_data, CompressionFormat::None);

    assert_eq!(index.entries.len(), 1);
    assert_eq!(index.get("empty.txt").unwrap().size, 0);

    let content = read_in_memory(&cpio_data, &index, "empty.txt");
    assert!(content.is_empty());
}

#[test]
fn test_cpio_compressed_all_formats() {
    let files = &[("test.txt", &b"Hello from cpio"[..])];
    let cpio_data = create_cpio_bytes(files);

    let formats: Vec<(CompressionFormat, Vec<u8>)> = vec![
        (CompressionFormat::Gzip, {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(&cpio_data).unwrap();
            e.finish().unwrap()
        }),
        (CompressionFormat::Bzip2, {
            let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
            e.write_all(&cpio_data).unwrap();
            e.finish().unwrap()
        }),
        (CompressionFormat::Xz, {
            let mut e = xz2::write::XzEncoder::new(Vec::new(), 6);
            e.write_all(&cpio_data).unwrap();
            e.finish().unwrap()
        }),
        (CompressionFormat::Zstd, {
            zstd::encode_all(std::io::Cursor::new(&cpio_data), 3).unwrap()
        }),
        (CompressionFormat::None, cpio_data.clone()),
    ];

    for (format, data) in &formats {
        let index = index_in_memory(data, *format);
        assert_eq!(
            index.metadata.archive_format,
            ArchiveFormat::Cpio,
            "format detection failed for {:?}",
            format
        );
        let content = read_in_memory(data, &index, "test.txt");
        assert_eq!(
            &content,
            b"Hello from cpio",
            "content mismatch for {:?}",
            format
        );
    }
}

