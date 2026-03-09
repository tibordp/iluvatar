//! Integration tests exercising zstd and xz decompressors through the engine API
//! with diverse data patterns and compression settings.

use std::io::Write;

use iluvatar::compress::CompressionFormat;
use iluvatar::engine::request::EngineRequest;
use iluvatar::engine::state_machine::{IndexingEngine, ReadEngine, DEFAULT_CHECKPOINT_INTERVAL};
use iluvatar::index::store::ArchiveIndex;

// ─── Helpers ───

/// Simple deterministic PRNG.
fn prng_data(seed: u64, size: usize) -> Vec<u8> {
    let mut state = seed;
    (0..size)
        .map(|_| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u8
        })
        .collect()
}

/// Create a tar archive in memory.
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

fn compress_tar_zstd(tar_data: &[u8], level: i32) -> Vec<u8> {
    zstd::encode_all(std::io::Cursor::new(tar_data), level).unwrap()
}

fn compress_tar_xz(tar_data: &[u8], preset: u32) -> Vec<u8> {
    let mut encoder = xz2::write::XzEncoder::new(Vec::new(), preset);
    encoder.write_all(tar_data).unwrap();
    encoder.finish().unwrap()
}

fn compress_tar_xz_multiblock(tar_data: &[u8], preset: u32, block_size: u64) -> Vec<u8> {
    use xz2::stream::{Check, MtStreamBuilder};
    let stream = MtStreamBuilder::new()
        .threads(1)
        .block_size(block_size)
        .preset(preset)
        .check(Check::Crc64)
        .encoder()
        .unwrap();
    let mut encoder = xz2::write::XzEncoder::new_stream(Vec::new(), stream);
    encoder.write_all(tar_data).unwrap();
    encoder.finish().unwrap()
}

fn compress_tar_zstd_multiframe(tar_data: &[u8], frame_size: usize) -> Vec<u8> {
    let mut result = Vec::new();
    for chunk in tar_data.chunks(frame_size) {
        result.extend_from_slice(&zstd::encode_all(std::io::Cursor::new(chunk), 1).unwrap());
    }
    result
}

/// Drive indexing engine with in-memory data and a specific chunk size.
fn index_in_memory_chunked(
    data: &[u8],
    format: CompressionFormat,
    chunk_size: usize,
    checkpoint_interval: u64,
) -> ArchiveIndex {
    let mut engine =
        IndexingEngine::new(format, None, checkpoint_interval, data.len() as u64).unwrap();
    let mut offset = 0;

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

fn index_in_memory(data: &[u8], format: CompressionFormat) -> ArchiveIndex {
    index_in_memory_chunked(data, format, 8192, DEFAULT_CHECKPOINT_INTERVAL)
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
            EngineRequest::Error(e) => panic!("read error: {}", e),
        }
    }

    result
}

/// Round-trip test: create tar, compress, index, read back each file.
fn roundtrip_test(compressed: &[u8], format: CompressionFormat, files: &[(&str, &[u8])]) {
    let index = index_in_memory(compressed, format);
    for (path, expected) in files {
        let actual = read_in_memory(compressed, &index, path);
        assert_eq!(
            actual, *expected,
            "content mismatch for '{}' (got {} bytes, expected {})",
            path,
            actual.len(),
            expected.len()
        );
    }
}

// ─── Zstd engine-level tests ───

#[test]
fn test_zstd_levels_roundtrip() {
    let file_a = prng_data(1, 30_000);
    let file_b = prng_data(2, 50_000);
    let tar = create_tar_bytes(&[("a.bin", &file_a), ("b.bin", &file_b)]);

    for level in [1, 3, 6, 9, 15, 19] {
        let compressed = compress_tar_zstd(&tar, level);
        roundtrip_test(
            &compressed,
            CompressionFormat::Zstd,
            &[("a.bin", &file_a), ("b.bin", &file_b)],
        );
    }
}

#[test]
fn test_zstd_multiframe_engine() {
    let file_data = prng_data(42, 80_000);
    let tar = create_tar_bytes(&[("data.bin", &file_data)]);

    for frame_size in [2048, 8192, 32768] {
        let compressed = compress_tar_zstd_multiframe(&tar, frame_size);
        roundtrip_test(
            &compressed,
            CompressionFormat::Zstd,
            &[("data.bin", &file_data)],
        );
    }
}

#[test]
fn test_zstd_many_small_files() {
    let files: Vec<(String, Vec<u8>)> = (0..100)
        .map(|i| {
            let size = (i * 47 + 3) % 5000;
            (format!("file_{:03}.bin", i), prng_data(i as u64, size))
        })
        .collect();
    let file_refs: Vec<(&str, &[u8])> = files.iter().map(|(n, d)| (n.as_str(), d.as_slice())).collect();
    let tar = create_tar_bytes(&file_refs);
    let compressed = compress_tar_zstd(&tar, 3);
    roundtrip_test(&compressed, CompressionFormat::Zstd, &file_refs);
}

#[test]
fn test_zstd_checkpoint_range_reads() {
    // Large file with small checkpoint interval, verify range reads from various offsets.
    let file_data = prng_data(12345, 200_000);
    let tar = create_tar_bytes(&[("big.bin", &file_data)]);
    let compressed = compress_tar_zstd(&tar, 3);

    let index = index_in_memory_chunked(
        &compressed,
        CompressionFormat::Zstd,
        8192,
        32_768, // 32 KB checkpoint interval
    );

    // Verify we got multiple checkpoints
    assert!(
        index.checkpoints.len() > 1,
        "expected multiple checkpoints, got {}",
        index.checkpoints.len()
    );

    // Read full file
    let full = read_in_memory(&compressed, &index, "big.bin");
    assert_eq!(full, file_data);

    // Range reads at various offsets
    for &(offset, len) in &[
        (0u64, 100u64),
        (1000, 5000),
        (50_000, 10_000),
        (100_000, 50_000),
        (190_000, 10_000),
        (0, 200_000),
    ] {
        let range = read_range_in_memory(&compressed, &index, "big.bin", offset, len);
        let expected = &file_data[offset as usize..(offset + len) as usize];
        assert_eq!(
            range, expected,
            "range read mismatch at offset={offset}, len={len}"
        );
    }
}

#[test]
fn test_zstd_edge_cases() {
    // Empty file, single byte, all zeros, all 0xFF
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty.bin", vec![]),
        ("one.bin", vec![42]),
        ("zeros.bin", vec![0u8; 50_000]),
        ("ones.bin", vec![0xFFu8; 50_000]),
    ];
    let file_refs: Vec<(&str, &[u8])> =
        cases.iter().map(|(n, d)| (*n, d.as_slice())).collect();
    let tar = create_tar_bytes(&file_refs);
    let compressed = compress_tar_zstd(&tar, 3);
    roundtrip_test(&compressed, CompressionFormat::Zstd, &file_refs);
}

#[test]
fn test_zstd_small_engine_chunks() {
    // Feed engine in 128-byte chunks to stress decompressor buffering.
    let file_data = prng_data(333, 20_000);
    let tar = create_tar_bytes(&[("data.bin", &file_data)]);
    let compressed = compress_tar_zstd(&tar, 3);

    let index = index_in_memory_chunked(&compressed, CompressionFormat::Zstd, 128, DEFAULT_CHECKPOINT_INTERVAL);
    let actual = read_in_memory(&compressed, &index, "data.bin");
    assert_eq!(actual, file_data);
}

// ─── XZ engine-level tests ───

#[test]
fn test_xz_presets_roundtrip() {
    let file_a = prng_data(1, 30_000);
    let file_b = prng_data(2, 50_000);
    let tar = create_tar_bytes(&[("a.bin", &file_a), ("b.bin", &file_b)]);

    for preset in [0, 3, 6, 9] {
        let compressed = compress_tar_xz(&tar, preset);
        roundtrip_test(
            &compressed,
            CompressionFormat::Xz,
            &[("a.bin", &file_a), ("b.bin", &file_b)],
        );
    }
}

#[test]
fn test_xz_multiblock_engine() {
    let file_data = prng_data(42, 80_000);
    let tar = create_tar_bytes(&[("data.bin", &file_data)]);

    for block_size in [4096u64, 16384, 65536] {
        let compressed = compress_tar_xz_multiblock(&tar, 6, block_size);
        roundtrip_test(
            &compressed,
            CompressionFormat::Xz,
            &[("data.bin", &file_data)],
        );
    }
}

#[test]
fn test_xz_many_small_files() {
    let files: Vec<(String, Vec<u8>)> = (0..100)
        .map(|i| {
            let size = (i * 47 + 3) % 5000;
            (format!("file_{:03}.bin", i), prng_data(i as u64, size))
        })
        .collect();
    let file_refs: Vec<(&str, &[u8])> = files.iter().map(|(n, d)| (n.as_str(), d.as_slice())).collect();
    let tar = create_tar_bytes(&file_refs);
    let compressed = compress_tar_xz(&tar, 3);
    roundtrip_test(&compressed, CompressionFormat::Xz, &file_refs);
}

#[test]
fn test_xz_checkpoint_range_reads() {
    let file_data = prng_data(12345, 200_000);
    let tar = create_tar_bytes(&[("big.bin", &file_data)]);
    let compressed = compress_tar_xz(&tar, 3);

    let index = index_in_memory_chunked(
        &compressed,
        CompressionFormat::Xz,
        8192,
        32_768,
    );

    assert!(
        index.checkpoints.len() > 1,
        "expected multiple checkpoints, got {}",
        index.checkpoints.len()
    );

    let full = read_in_memory(&compressed, &index, "big.bin");
    assert_eq!(full, file_data);

    for &(offset, len) in &[
        (0u64, 100u64),
        (1000, 5000),
        (50_000, 10_000),
        (100_000, 50_000),
        (190_000, 10_000),
        (0, 200_000),
    ] {
        let range = read_range_in_memory(&compressed, &index, "big.bin", offset, len);
        let expected = &file_data[offset as usize..(offset + len) as usize];
        assert_eq!(
            range, expected,
            "range read mismatch at offset={offset}, len={len}"
        );
    }
}

#[test]
fn test_xz_edge_cases() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty.bin", vec![]),
        ("one.bin", vec![42]),
        ("zeros.bin", vec![0u8; 50_000]),
        ("ones.bin", vec![0xFFu8; 50_000]),
    ];
    let file_refs: Vec<(&str, &[u8])> =
        cases.iter().map(|(n, d)| (*n, d.as_slice())).collect();
    let tar = create_tar_bytes(&file_refs);
    let compressed = compress_tar_xz(&tar, 3);
    roundtrip_test(&compressed, CompressionFormat::Xz, &file_refs);
}

#[test]
fn test_xz_small_engine_chunks() {
    let file_data = prng_data(333, 20_000);
    let tar = create_tar_bytes(&[("data.bin", &file_data)]);
    let compressed = compress_tar_xz(&tar, 3);

    let index = index_in_memory_chunked(&compressed, CompressionFormat::Xz, 128, DEFAULT_CHECKPOINT_INTERVAL);
    let actual = read_in_memory(&compressed, &index, "data.bin");
    assert_eq!(actual, file_data);
}

// ─── Cross-format comparison ───

#[test]
fn test_same_data_all_compressed_formats() {
    // Same tar archive compressed with every format should produce identical file contents.
    let file_a = prng_data(100, 25_000);
    let file_b = vec![0u8; 10_000];
    let file_c = prng_data(200, 50_000);
    let tar = create_tar_bytes(&[("a.bin", &file_a), ("b.bin", &file_b), ("c.bin", &file_c)]);

    let formats: Vec<(CompressionFormat, Vec<u8>)> = vec![
        (CompressionFormat::Zstd, compress_tar_zstd(&tar, 3)),
        (CompressionFormat::Xz, compress_tar_xz(&tar, 6)),
    ];

    for (format, compressed) in &formats {
        let index = index_in_memory(compressed, *format);
        let a = read_in_memory(compressed, &index, "a.bin");
        let b = read_in_memory(compressed, &index, "b.bin");
        let c = read_in_memory(compressed, &index, "c.bin");
        assert_eq!(a, file_a, "a.bin mismatch for {:?}", format);
        assert_eq!(b, file_b, "b.bin mismatch for {:?}", format);
        assert_eq!(c, file_c, "c.bin mismatch for {:?}", format);
    }
}
