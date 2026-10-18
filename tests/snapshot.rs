//! Index snapshots share checkpoint state with the indexing engine, stay
//! readable while indexing continues, and leave the serialized form alone.
#![cfg(all(
    feature = "gzip",
    feature = "bz2",
    feature = "xz",
    feature = "zstandard"
))]

use std::io::Write;
use std::sync::Arc;

use iluvatar::{
    ArchiveIndex, CheckpointStrategy, CompressionFormat, EngineRequest, FixedInterval,
    IndexingEngine, ReadEngine, ThinningBudget,
};

// ─── Helpers ───

fn incompressible(seed: u64, len: usize) -> Vec<u8> {
    let mut rng = seed;
    (0..len)
        .map(|_| {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            (rng >> 33) as u8
        })
        .collect()
}

/// Mixed random and repetitive files, enough for many 32 KiB checkpoints.
fn files() -> Vec<(String, Vec<u8>)> {
    (0..24u64)
        .map(|i| {
            let data = if i % 2 == 0 {
                incompressible(i + 1, 40_000 + i as usize * 1009)
            } else {
                (0..30_000 + i as usize * 1511)
                    .map(|j| b"lorem ipsum dolor\n"[(j + i as usize) % 18])
                    .collect()
            };
            (format!("d{}/f{i:02}", i % 3), data)
        })
        .collect()
}

fn tar_bytes(files: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, data) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(1700000000);
        header.set_cksum();
        builder.append_data(&mut header, path, &data[..]).unwrap();
    }
    builder.into_inner().unwrap()
}

/// The archive under each codec the tests cover.
fn archives(files: &[(String, Vec<u8>)]) -> Vec<(&'static str, CompressionFormat, Vec<u8>)> {
    let tar = tar_bytes(files);
    let gz = {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(&tar).unwrap();
        e.finish().unwrap()
    };
    let bz2 = {
        // 100 KB blocks, so bzip2 has block boundaries to checkpoint at.
        let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::new(1));
        e.write_all(&tar).unwrap();
        e.finish().unwrap()
    };
    let xz = {
        let mut e = xz2::write::XzEncoder::new(Vec::new(), 6);
        e.write_all(&tar).unwrap();
        e.finish().unwrap()
    };
    let zst = zstd::encode_all(std::io::Cursor::new(&tar), 3).unwrap();
    vec![
        ("gzip", CompressionFormat::Gzip, gz),
        ("bzip2", CompressionFormat::Bzip2, bz2),
        ("xz", CompressionFormat::Xz, xz),
        ("zstd", CompressionFormat::Zstd, zst),
    ]
}

/// Index `data`, calling `on_step` with the engine after every input chunk.
fn index_with<S: CheckpointStrategy>(
    data: &[u8],
    format: CompressionFormat,
    strategy: S,
    mut on_step: impl FnMut(&IndexingEngine<S>),
) -> ArchiveIndex {
    let mut engine =
        IndexingEngine::with_strategy(format, None, strategy, data.len() as u64).unwrap();
    let mut offset = 0;
    loop {
        match engine.step() {
            EngineRequest::NeedInput => {
                if offset >= data.len() {
                    engine.signal_eof();
                } else {
                    let end = (offset + 8192).min(data.len());
                    engine.provide_data(&data[offset..end]);
                    offset = end;
                    on_step(&engine);
                }
            }
            EngineRequest::Done => break,
            EngineRequest::Error(e) => panic!("indexing error: {e}"),
            _ => {}
        }
    }
    engine.finish()
}

fn read_entry(data: &[u8], index: &ArchiveIndex, entry: &iluvatar::IndexEntry) -> Vec<u8> {
    let mut engine = ReadEngine::for_entry(index, entry).unwrap();
    let mut out = Vec::new();
    let mut offset = 0;
    loop {
        match engine.step() {
            EngineRequest::NeedInput => {
                if offset >= data.len() {
                    engine.signal_eof();
                } else {
                    let end = (offset + 8192).min(data.len());
                    engine.provide_data(&data[offset..end]);
                    offset = end;
                }
            }
            EngineRequest::SeekAndRead { offset: off, len } => {
                let start = off as usize;
                if start >= data.len() {
                    engine.signal_eof();
                } else {
                    let end = (start + len).min(data.len());
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
                    out.extend_from_slice(&buf[..n]);
                }
            }
            EngineRequest::Done => break,
            EngineRequest::Error(e) => panic!("read error: {e}"),
        }
    }
    out
}

/// Every entry `index` lists reads back as the archive holds it.
fn assert_reads_match(name: &str, data: &[u8], index: &ArchiveIndex, files: &[(String, Vec<u8>)]) {
    for entry in index.entries() {
        let expected = &files.iter().find(|(p, _)| *p == entry.path).unwrap().1;
        assert!(
            read_entry(data, index, entry) == *expected,
            "{name}: {} differs",
            entry.path
        );
    }
}

fn contains_ptr(index: &ArchiveIndex, cp: &Arc<iluvatar::Checkpoint>) -> bool {
    index.checkpoints().iter().any(|c| Arc::ptr_eq(c, cp))
}

// ─── Sharing ───

#[test]
fn snapshot_shares_checkpoints_with_the_engine() {
    let files = files();
    for (name, format, data) in archives(&files) {
        let mut snapshots = Vec::new();
        let index = index_with(&data, format, FixedInterval::new(32 * 1024), |engine| {
            let (a, b) = (engine.snapshot_index(), engine.snapshot_index());
            assert_eq!(a.checkpoints().len(), b.checkpoints().len());
            assert!(
                a.checkpoints()
                    .iter()
                    .zip(b.checkpoints())
                    .all(|(x, y)| Arc::ptr_eq(x, y)),
                "{name}: two snapshots of the same state hold different checkpoints"
            );
            snapshots.push(a);
        });
        assert!(index.checkpoints().len() > 3, "{name}: too few checkpoints");
        // Nothing is thinned under a fixed interval, so every snapshot's
        // checkpoints are the final index's, not copies of them.
        for snap in &snapshots {
            for cp in snap.checkpoints() {
                assert!(
                    contains_ptr(&index, cp),
                    "{name}: snapshot copied a checkpoint"
                );
            }
        }
    }
}

// ─── Reading from snapshots ───

#[test]
fn mid_index_snapshots_read_like_the_final_index() {
    let files = files();
    for (name, format, data) in archives(&files) {
        // About eight snapshots over the stream.
        let every = (data.len() / 8192 / 8).max(1);
        let mut snapshots = Vec::new();
        let mut steps = 0;
        let index = index_with(&data, format, FixedInterval::new(32 * 1024), |engine| {
            steps += 1;
            if steps % every == 0 {
                snapshots.push(engine.snapshot_index());
            }
        });
        assert!(snapshots.len() >= 3, "{name}: too few snapshots");
        assert!(snapshots
            .iter()
            .any(|s| !s.is_empty() && s.len() < index.len()));
        assert_eq!(index.len(), files.len());
        assert_reads_match(name, &data, &index, &files);
        for snap in &snapshots {
            assert!(!snap.metadata.complete);
            assert_reads_match(name, &data, snap, &files);
        }
    }
}

#[test]
fn held_snapshot_survives_thinning_and_more_indexing() {
    let files = files();
    for (name, format, data) in archives(&files) {
        // A budget of a few checkpoints of this codec, so thinning happens.
        let dense = index_with(&data, format, FixedInterval::new(32 * 1024), |_| {});
        let real = dense.checkpoints().len() as u64 - 1;
        assert!(real > 4, "{name}: too few checkpoints");
        let budget = 4 * dense.stream.checkpoint_data_bytes() / real;

        let mut held: Option<ArchiveIndex> = None;
        let strategy = ThinningBudget::new(budget).with_min_interval(32 * 1024);
        let index = index_with(&data, format, strategy, |engine| {
            // Hold the first snapshot with a mid-stream checkpoint.
            if held.is_none() && engine.progress().checkpoints_created > 1 {
                held = Some(engine.snapshot_index());
            }
        });
        let held = held.unwrap_or_else(|| panic!("{name}: no mid-stream checkpoint"));
        assert!(
            held.checkpoints()
                .iter()
                .any(|cp| !contains_ptr(&index, cp)),
            "{name}: the engine thinned none of the held snapshot's checkpoints"
        );
        assert!(!held.is_empty(), "{name}: held snapshot lists nothing");
        assert_reads_match(name, &data, &held, &files);
        assert_reads_match(name, &data, &index, &files);
    }
}

// ─── Serialized form ───

#[test]
fn serialized_form_round_trips_unchanged() {
    let files = files();
    for (name, format, data) in archives(&files) {
        let index = index_with(&data, format, FixedInterval::new(32 * 1024), |_| {});
        let bytes = index.to_bytes().unwrap();
        let restored = ArchiveIndex::from_bytes(&bytes).unwrap();
        assert_eq!(restored.to_bytes().unwrap(), bytes, "{name}");
        assert_eq!(restored.checkpoints().len(), index.checkpoints().len());
        assert_reads_match(name, &data, &restored, &files);
    }
}

/// Indexes written by iluvatar 0.6.0 (see `tests/vectors/index_v0_6`) load,
/// read, and serialize back to the same bytes.
#[test]
fn loads_an_index_written_by_0_6() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/index_v0_6");
    for name in ["archive.tar.gz", "archive.tar.zst"] {
        let data = std::fs::read(dir.join(name)).unwrap();
        let bytes = std::fs::read(dir.join(format!("{name}.idx"))).unwrap();
        let index = ArchiveIndex::from_bytes(&bytes).unwrap();
        assert!(
            index.checkpoints().len() > 1,
            "{name}: want mid-stream checkpoints"
        );
        assert_eq!(
            index.to_bytes().unwrap(),
            bytes,
            "{name}: serialized form changed"
        );

        // Compare against the members as the tar crate reads them.
        let tar = match index.metadata.compression {
            CompressionFormat::Gzip => {
                let mut out = Vec::new();
                std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&data[..]), &mut out)
                    .unwrap();
                out
            }
            _ => zstd::decode_all(&data[..]).unwrap(),
        };
        let mut archive = tar::Archive::new(&tar[..]);
        let mut members = 0;
        for member in archive.entries().unwrap() {
            let mut member = member.unwrap();
            let path = member.path().unwrap().to_string_lossy().into_owned();
            let mut expected = Vec::new();
            std::io::Read::read_to_end(&mut member, &mut expected).unwrap();
            let entry = index.get(&path).unwrap();
            assert!(
                read_entry(&data, &index, entry) == expected,
                "{name}: {path}"
            );
            members += 1;
        }
        assert_eq!(members, index.len(), "{name}");
    }
}
