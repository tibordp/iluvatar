//! The stream layer against real encoders: bare compressed streams, raw
//! LZMA/LZMA2, xz2's BCJ filter chains, Delta, AES, partial indexing with
//! resume, and live-reader retargeting.

#![cfg(all(
    feature = "xz",
    feature = "gzip",
    feature = "zstandard",
    feature = "bz2"
))]

use std::io::Write;

use iluvatar::{
    BcjArch, Codec, CodecSpec, EngineRequest, FixedInterval, StreamIndex, StreamIndexer,
    StreamReader,
};

// ─── Data and encoders ───

/// Text-like runs mixed with noise: compressible enough to exercise LZ
/// matches, noisy enough that deflate emits block boundaries.
fn mixed(seed: u64, len: usize) -> Vec<u8> {
    let mut s = seed;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let r = (s >> 33) as u32;
        match r % 4 {
            0 => out.extend_from_slice(b"the quick brown fox jumps over the lazy dog "),
            1 => out.extend((0..(r % 200) as usize).map(|i| (i * 7) as u8)),
            2 => out.extend(std::iter::repeat((r >> 8) as u8).take((r % 300) as usize)),
            _ => out.extend((0..64).map(|_| {
                s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
                (s >> 33) as u8
            })),
        }
    }
    out.truncate(len);
    out
}

/// Machine-code-like data so BCJ converters find instructions to rewrite.
fn code_like(seed: u64, len: usize) -> Vec<u8> {
    let mut s = seed;
    let mut v = Vec::with_capacity(len + 16);
    while v.len() < len {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let r = (s >> 33) as u32;
        match r % 8 {
            0 => {
                v.push(0xE8);
                v.extend_from_slice(&((r >> 8) as i32 % 4096).to_le_bytes());
            }
            1 => v.extend_from_slice(&(0x9400_0000u32 | (r & 0x00FF_FFFF)).to_le_bytes()),
            2 => v.extend_from_slice(&(0xEB00_0000u32 | (r & 0x00FF_FFFF)).to_be_bytes()),
            3 => v.extend_from_slice(&(0x4800_0001u32 | (r & 0x03FF_FFFC)).to_be_bytes()),
            4 => v.extend_from_slice(&(0x4000_0000u32 | (r & 0x003F_FFFF)).to_be_bytes()),
            5 => v.extend_from_slice(&[
                (r & 0xFF) as u8,
                0xF0 | ((r >> 8) & 7) as u8,
                (r >> 16) as u8,
                0xF8,
            ]),
            _ => v.extend_from_slice(&r.to_le_bytes()),
        }
    }
    v.truncate(len);
    v
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn raw_deflate(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn bzip2(data: &[u8]) -> Vec<u8> {
    let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::new(1));
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn xz(data: &[u8]) -> Vec<u8> {
    let mut e = xz2::write::XzEncoder::new(Vec::new(), 6);
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn zstd(data: &[u8]) -> Vec<u8> {
    zstd::encode_all(std::io::Cursor::new(data), 3).unwrap()
}

/// Raw stream (no `.xz` container) through liblzma's filter-chain encoder:
/// the given BCJ filter, if any, in front of LZMA2 with a 1 MiB dictionary.
fn raw_xz(bcj: Option<lzma_sys::lzma_vli>, data: &[u8]) -> Vec<u8> {
    try_raw_xz(bcj, data).expect("liblzma raw encoder")
}

/// `None` when the bundled liblzma was built without this filter's encoder.
fn try_raw_xz(bcj: Option<lzma_sys::lzma_vli>, data: &[u8]) -> Option<Vec<u8>> {
    unsafe {
        let mut opts: lzma_sys::lzma_options_lzma = std::mem::zeroed();
        assert_eq!(lzma_sys::lzma_lzma_preset(&mut opts, 6), 0);
        opts.dict_size = 1 << 20;
        let mut filters = Vec::new();
        if let Some(id) = bcj {
            filters.push(lzma_sys::lzma_filter {
                id,
                options: std::ptr::null_mut(),
            });
        }
        filters.push(lzma_sys::lzma_filter {
            id: lzma_sys::LZMA_FILTER_LZMA2,
            options: &mut opts as *mut _ as *mut std::ffi::c_void,
        });
        filters.push(lzma_sys::lzma_filter {
            id: lzma_sys::LZMA_VLI_UNKNOWN,
            options: std::ptr::null_mut(),
        });
        let mut strm: lzma_sys::lzma_stream = std::mem::zeroed();
        if lzma_sys::lzma_raw_encoder(&mut strm, filters.as_ptr()) != lzma_sys::LZMA_OK {
            return None;
        }
        let mut out = vec![0u8; data.len() + data.len() / 2 + 4096];
        strm.next_in = data.as_ptr();
        strm.avail_in = data.len();
        strm.next_out = out.as_mut_ptr();
        strm.avail_out = out.len();
        let ret = lzma_sys::lzma_code(&mut strm, lzma_sys::LZMA_FINISH);
        assert_eq!(ret, lzma_sys::LZMA_STREAM_END);
        out.truncate(strm.total_out as usize);
        lzma_sys::lzma_end(&mut strm);
        Some(out)
    }
}

fn lzma_opts() -> xz2::stream::LzmaOptions {
    let mut o = xz2::stream::LzmaOptions::new_preset(6).unwrap();
    o.dict_size(1 << 20);
    o
}

/// `dict_prop` for a 1 MiB dictionary: `2 << (p/2 + 11)` with p even.
const LZMA2_1MIB: u8 = 18;

fn raw_lzma2(data: &[u8]) -> Vec<u8> {
    raw_xz(None, data)
}

/// `.lzma` (LZMA-alone) stripped of its 13-byte header: props, dict size,
/// unknown length. The stream then ends with an end marker.
fn raw_lzma1(data: &[u8]) -> (u8, u32, Vec<u8>) {
    let stream = xz2::stream::Stream::new_lzma_encoder(&lzma_opts()).unwrap();
    let mut e = xz2::write::XzEncoder::new_stream(Vec::new(), stream);
    e.write_all(data).unwrap();
    let alone = e.finish().unwrap();
    let props = alone[0];
    let dict = u32::from_le_bytes([alone[1], alone[2], alone[3], alone[4]]);
    (props, dict, alone[13..].to_vec())
}

// ─── Drivers ───

fn index_stream(
    compressed: &[u8],
    codec: CodecSpec,
    interval: u64,
    chunk: usize,
    stop_at: Option<u64>,
) -> StreamIndex {
    let mut indexer = StreamIndexer::new(
        codec,
        FixedInterval::new(interval),
        Some(compressed.len() as u64),
    )
    .unwrap();
    if let Some(stop) = stop_at {
        indexer.stop_at(stop);
    }
    drive_indexer(&mut indexer, compressed, chunk, 0);
    indexer.finish()
}

/// Feed `compressed` from `offset` on, honouring seeks.
fn drive_indexer(
    indexer: &mut StreamIndexer<FixedInterval>,
    compressed: &[u8],
    chunk: usize,
    mut offset: usize,
) {
    loop {
        match indexer.step() {
            EngineRequest::NeedInput => {
                if offset >= compressed.len() {
                    indexer.signal_eof();
                } else {
                    let end = (offset + chunk).min(compressed.len());
                    indexer.provide_data(&compressed[offset..end]);
                    offset = end;
                }
            }
            EngineRequest::SeekAndRead { offset: off, len } => {
                offset = off as usize;
                let end = (offset + len.min(chunk)).min(compressed.len());
                if offset >= compressed.len() {
                    indexer.signal_eof();
                } else {
                    indexer.provide_data(&compressed[offset..end]);
                    offset = end;
                }
            }
            EngineRequest::OutputReady => {
                let mut buf = [0u8; 4096];
                while indexer.read_output(&mut buf) > 0 {}
            }
            EngineRequest::Done => break,
            EngineRequest::Error(e) => panic!("indexing: {}", e),
        }
    }
}

/// A live reader keeps its place in the packed stream between calls.
fn drive_reader(reader: &mut StreamReader, compressed: &[u8], chunk: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut offset = reader.compressed_position() as usize;
    let mut buf = vec![0u8; 3000];
    loop {
        match reader.step() {
            EngineRequest::NeedInput => {
                if offset >= compressed.len() {
                    reader.signal_eof();
                } else {
                    let end = (offset + chunk).min(compressed.len());
                    reader.provide_data(&compressed[offset..end]);
                    offset = end;
                }
            }
            EngineRequest::SeekAndRead { offset: off, len } => {
                offset = off as usize;
                if offset >= compressed.len() {
                    reader.signal_eof();
                } else {
                    let end = (offset + len.min(chunk)).min(compressed.len());
                    reader.provide_data(&compressed[offset..end]);
                    offset = end;
                }
            }
            EngineRequest::OutputReady => loop {
                let n = reader.read_output(&mut buf);
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n]);
            },
            EngineRequest::Done => break,
            EngineRequest::Error(e) => panic!("reading: {}", e),
        }
    }
    out
}

fn read_range(index: &StreamIndex, compressed: &[u8], offset: u64, len: u64) -> Vec<u8> {
    let mut reader = StreamReader::new(index, offset, len).unwrap();
    drive_reader(&mut reader, compressed, 4096)
}

/// Random ranges, a range past the end, and a range at the end.
fn check_random_access(index: &StreamIndex, compressed: &[u8], plain: &[u8]) {
    assert!(index.complete);
    assert_eq!(index.unpacked_len, Some(plain.len() as u64));
    let mut s = 42u64;
    for _ in 0..40 {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
        let off = (s >> 33) as usize % plain.len();
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
        let len = 1 + (s >> 33) as usize % 20_000;
        let expect = &plain[off..(off + len).min(plain.len())];
        assert_eq!(
            read_range(index, compressed, off as u64, len as u64),
            expect
        );
    }
    assert_eq!(
        read_range(index, compressed, plain.len() as u64 - 10, 1000),
        &plain[plain.len() - 10..]
    );
    assert!(read_range(index, compressed, plain.len() as u64, 10).is_empty());
    assert!(read_range(index, compressed, plain.len() as u64 + 5, 10).is_empty());
}

/// Every checkpoint must reproduce the stream tail exactly.
fn check_checkpoints_resume(index: &StreamIndex, compressed: &[u8], plain: &[u8]) {
    assert!(
        index.checkpoints.len() > 2,
        "want several checkpoints, got {}",
        index.checkpoints.len()
    );
    for cp in &index.checkpoints {
        let off = cp.uncompressed_offset;
        let tail = read_range(index, compressed, off, plain.len() as u64 - off);
        assert_eq!(
            tail,
            &plain[off as usize..],
            "tail from checkpoint at {}",
            off
        );
    }
}

// ─── Bare streams ───

#[test]
fn bare_streams_random_access() {
    let plain = mixed(1, 700_000);
    let cases: Vec<(&str, Vec<u8>, CodecSpec)> = vec![
        (
            "gzip",
            gzip(&plain),
            CodecSpec::single(Codec::Deflate { raw: false }),
        ),
        (
            "deflate",
            raw_deflate(&plain),
            CodecSpec::single(Codec::Deflate { raw: true }),
        ),
        ("bzip2", bzip2(&plain), CodecSpec::single(Codec::Bzip2)),
        ("xz", xz(&plain), CodecSpec::single(Codec::Xz)),
        ("zstd", zstd(&plain), CodecSpec::single(Codec::Zstd)),
        (
            "lzma2",
            raw_lzma2(&plain),
            CodecSpec::single(Codec::Lzma2 {
                dict_prop: LZMA2_1MIB,
            }),
        ),
    ];
    for (name, compressed, codec) in cases {
        let index = index_stream(&compressed, codec, 64 * 1024, 5000, None);
        check_random_access(&index, &compressed, &plain);
        check_checkpoints_resume(&index, &compressed, &plain);
        eprintln!("{}: {} checkpoints", name, index.checkpoints.len());
    }
}

#[test]
fn raw_lzma1_with_end_marker_and_with_known_length() {
    let plain = mixed(2, 300_000);
    let (props, dict_size, raw) = raw_lzma1(&plain);
    for unpacked_len in [None, Some(plain.len() as u64)] {
        let codec = CodecSpec::single(Codec::Lzma {
            props,
            dict_size,
            unpacked_len,
        });
        let index = index_stream(&raw, codec, 32 * 1024, 4096, None);
        check_random_access(&index, &raw, &plain);
        check_checkpoints_resume(&index, &raw, &plain);
    }
}

// ─── Chains ───

#[test]
fn bcj_chains_from_liblzma() {
    let plain = code_like(3, 400_000);
    let archs = [
        (BcjArch::X86, lzma_sys::LZMA_FILTER_X86),
        (BcjArch::Arm, lzma_sys::LZMA_FILTER_ARM),
        (BcjArch::ArmThumb, lzma_sys::LZMA_FILTER_ARMTHUMB),
        (BcjArch::PowerPc, lzma_sys::LZMA_FILTER_POWERPC),
        (BcjArch::Sparc, lzma_sys::LZMA_FILTER_SPARC),
        (BcjArch::Ia64, lzma_sys::LZMA_FILTER_IA64),
    ];
    let mut tested = 0;
    for (arch, id) in archs {
        let Some(compressed) = try_raw_xz(Some(id), &plain) else {
            eprintln!("liblzma has no {:?} encoder; skipping", arch);
            continue;
        };
        tested += 1;
        let codec = CodecSpec(vec![
            Codec::Lzma2 {
                dict_prop: LZMA2_1MIB,
            },
            Codec::Bcj(arch),
        ]);
        let index = index_stream(&compressed, codec, 48 * 1024, 3000, None);
        check_random_access(&index, &compressed, &plain);
        check_checkpoints_resume(&index, &compressed, &plain);
    }
    assert!(tested >= 2, "liblzma should encode at least x86 and SPARC");
}

#[test]
fn delta_chain() {
    let plain = mixed(4, 200_000);
    for distance in [1u8, 3, 255] {
        let d = distance as usize + 1;
        let mut encoded = plain.clone();
        for i in (d..encoded.len()).rev() {
            encoded[i] = encoded[i].wrapping_sub(plain[i - d]);
        }
        let compressed = raw_lzma2(&encoded);
        let codec = CodecSpec(vec![
            Codec::Lzma2 {
                dict_prop: LZMA2_1MIB,
            },
            Codec::Delta { distance },
        ]);
        let index = index_stream(&compressed, codec, 32 * 1024, 2000, None);
        check_random_access(&index, &compressed, &plain);
        check_checkpoints_resume(&index, &compressed, &plain);
    }
}

#[cfg(feature = "aes")]
#[test]
fn aes_chain_and_key_is_not_serialized() {
    use aes::cipher::{BlockEncrypt, KeyInit};
    let plain = mixed(5, 300_000);
    let packed = raw_lzma2(&plain);
    let key = [0x5Au8; 32];
    let iv = [0xA5u8; 16];

    let cipher = aes::Aes256::new(&key.into());
    let mut prev = iv;
    let mut encrypted = Vec::new();
    let mut padded = packed.clone();
    padded.resize(packed.len().div_ceil(16) * 16, 0);
    for chunk in padded.chunks(16) {
        let mut b = [0u8; 16];
        for (i, (c, p)) in chunk.iter().zip(prev.iter()).enumerate() {
            b[i] = c ^ p;
        }
        cipher.encrypt_block((&mut b).into());
        encrypted.extend_from_slice(&b);
        prev = b;
    }

    let codec = CodecSpec(vec![
        Codec::AesCbc {
            key: Some(key),
            iv,
            len: Some(packed.len() as u64),
        },
        Codec::Lzma2 {
            dict_prop: LZMA2_1MIB,
        },
    ]);
    let index = index_stream(&encrypted, codec, 32 * 1024, 1000, None);
    check_random_access(&index, &encrypted, &plain);
    check_checkpoints_resume(&index, &encrypted, &plain);

    // The key does not survive serialization; reading fails until it is
    // supplied again.
    let bytes = bincode::serialize(&index).unwrap();
    let mut restored: StreamIndex = bincode::deserialize(&bytes).unwrap();
    assert!(StreamReader::new(&restored, 0, 10).is_err());
    restored.codec.set_aes_key(key);
    assert_eq!(
        read_range(&restored, &encrypted, 1000, 100),
        &plain[1000..1100]
    );
}

#[test]
fn chain_of_three() {
    // Delta on top of an x86-filtered LZMA2 stream is contrived but exercises
    // pending bytes between two filter stages.
    let plain = code_like(6, 150_000);
    let mut encoded = plain.clone();
    for i in (2..encoded.len()).rev() {
        encoded[i] = encoded[i].wrapping_sub(plain[i - 2]);
    }
    let compressed = raw_xz(Some(lzma_sys::LZMA_FILTER_X86), &encoded);
    let codec = CodecSpec(vec![
        Codec::Lzma2 {
            dict_prop: LZMA2_1MIB,
        },
        Codec::Bcj(BcjArch::X86),
        Codec::Delta { distance: 1 },
    ]);
    let index = index_stream(&compressed, codec, 16 * 1024, 777, None);
    check_random_access(&index, &compressed, &plain);
    check_checkpoints_resume(&index, &compressed, &plain);
}

// ─── Partial indexing and resume ───

#[test]
fn stop_at_then_resume_extends_the_index() {
    let plain = mixed(7, 600_000);
    let compressed = xz(&plain);
    let codec = CodecSpec::single(Codec::Xz);

    let partial = index_stream(&compressed, codec.clone(), 50_000, 4096, Some(200_000));
    assert!(!partial.complete);
    assert!(partial.indexed_to >= 200_000);
    assert!(partial.indexed_to < plain.len() as u64);
    // The stop point carries a checkpoint, so resume costs no re-decode.
    assert_eq!(
        partial.last_checkpoint().uncompressed_offset,
        partial.indexed_to
    );
    // Reads inside the indexed part work; a read past it still decodes forward.
    assert_eq!(
        read_range(&partial, &compressed, 150_000, 1000),
        &plain[150_000..151_000]
    );
    assert_eq!(
        read_range(&partial, &compressed, 400_000, 1000),
        &plain[400_000..401_000]
    );

    let before = partial.checkpoints.len();
    let mut indexer = StreamIndexer::resume(partial, FixedInterval::new(50_000)).unwrap();
    // A resumed indexer must seek to its checkpoint, never re-read from 0.
    let resume_at = match indexer.step() {
        EngineRequest::SeekAndRead { offset, .. } => offset as usize,
        other => panic!("expected SeekAndRead, got {:?}", other),
    };
    assert!(resume_at > 0);
    indexer.provide_data(&compressed[resume_at..resume_at + 4096]);
    drive_indexer(&mut indexer, &compressed, 4096, resume_at + 4096);
    let full = indexer.finish();
    assert!(full.complete);
    assert!(full.checkpoints.len() > before);
    assert!(full
        .checkpoints
        .windows(2)
        .all(|w| w[0].uncompressed_offset < w[1].uncompressed_offset));
    check_random_access(&full, &compressed, &plain);
    check_checkpoints_resume(&full, &compressed, &plain);

    let one_pass = index_stream(&compressed, codec, 50_000, 4096, None);
    assert_eq!(one_pass.unpacked_len, full.unpacked_len);
}

#[test]
fn resume_in_several_increments() {
    let plain = mixed(8, 500_000);
    let compressed = zstd(&plain);
    let codec = CodecSpec::single(Codec::Zstd);
    let mut index = index_stream(&compressed, codec, 40_000, 3000, Some(100_000));
    for stop in [250_000u64, 380_000, u64::MAX] {
        let mut indexer = StreamIndexer::resume(index, FixedInterval::new(40_000)).unwrap();
        indexer.stop_at(stop);
        drive_indexer(&mut indexer, &compressed, 3000, 0);
        index = indexer.finish();
        assert_eq!(index.complete, stop == u64::MAX);
    }
    check_random_access(&index, &compressed, &plain);
    check_checkpoints_resume(&index, &compressed, &plain);
}

// ─── Live readers ───

#[test]
fn seek_forward_serves_sequential_and_jumping_reads() {
    let plain = mixed(9, 400_000);
    let compressed = xz(&plain);
    let index = index_stream(
        &compressed,
        CodecSpec::single(Codec::Xz),
        64 * 1024,
        4096,
        None,
    );

    let mut reader = StreamReader::new(&index, 10_000, 5_000).unwrap();
    let mut got = drive_reader(&mut reader, &compressed, 4096);
    assert_eq!(reader.position(), 15_000);
    // Contiguous chunks, some smaller than a decode step, one larger.
    for (off, len) in [(15_000u64, 100u64), (15_100, 70_000), (85_100, 1)] {
        reader.seek_forward(off, len).unwrap();
        got.extend_from_slice(&drive_reader(&mut reader, &compressed, 4096));
        assert_eq!(reader.position(), off + len);
    }
    assert_eq!(got, &plain[10_000..85_101]);

    // A jump well past the decoder's position, then a jump within what it
    // has already buffered.
    reader.seek_forward(300_000, 2_000).unwrap();
    assert_eq!(
        drive_reader(&mut reader, &compressed, 4096),
        &plain[300_000..302_000]
    );
    reader.seek_forward(302_500, 100).unwrap();
    assert_eq!(
        drive_reader(&mut reader, &compressed, 4096),
        &plain[302_500..302_600]
    );

    // Backwards is refused; past the end yields nothing.
    assert!(reader.seek_forward(1, 10).is_err());
    reader.seek_forward(plain.len() as u64 + 100, 10).unwrap();
    assert!(drive_reader(&mut reader, &compressed, 4096).is_empty());
}

/// A reader retargeted after the decoder hit the end of the stream still
/// serves what that last decode left undelivered.
#[test]
fn seek_forward_after_the_decoder_reached_stream_end() {
    let plain = mixed(4, 215_040);
    for (compressed, codec) in [
        (gzip(&plain), Codec::Deflate { raw: false }),
        (xz(&plain), Codec::Xz),
        (bzip2(&plain), Codec::Bzip2),
        (zstd(&plain), Codec::Zstd),
    ] {
        let index = index_stream(&compressed, CodecSpec::single(codec), 1 << 20, 4096, None);
        let mut reader = StreamReader::new(&index, 0, 100_000).unwrap();
        let mut got = drive_reader(&mut reader, &compressed, 1 << 20);
        for (off, len) in [(100_000u64, 100_000u64), (200_000, 15_040)] {
            reader.seek_forward(off, len).unwrap();
            got.extend_from_slice(&drive_reader(&mut reader, &compressed, 1 << 20));
        }
        assert_eq!(got.len(), plain.len());
        assert!(got == plain);
    }
}

#[test]
fn indexer_can_hand_out_its_output() {
    let plain = mixed(10, 100_000);
    let compressed = gzip(&plain);
    let mut indexer = StreamIndexer::new(
        CodecSpec::single(Codec::Deflate { raw: false }),
        FixedInterval::new(1 << 20),
        None,
    )
    .unwrap();
    indexer.emit_output(true);
    let mut seen = Vec::new();
    let mut offset = 0;
    loop {
        match indexer.step() {
            EngineRequest::NeedInput => {
                if offset >= compressed.len() {
                    indexer.signal_eof();
                } else {
                    let end = (offset + 1000).min(compressed.len());
                    indexer.provide_data(&compressed[offset..end]);
                    offset = end;
                }
            }
            EngineRequest::OutputReady => {
                let mut buf = [0u8; 777];
                loop {
                    let n = indexer.read_output(&mut buf);
                    if n == 0 {
                        break;
                    }
                    seen.extend_from_slice(&buf[..n]);
                }
            }
            EngineRequest::Done => break,
            other => panic!("unexpected {:?}", other),
        }
    }
    assert_eq!(seen, plain);
    let index = indexer.finish();
    assert!(index.complete);
    assert_eq!(index.unpacked_len, Some(plain.len() as u64));
}
