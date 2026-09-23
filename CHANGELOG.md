# Changelog

## 0.4.0 — unreleased

### Added

- **Stream layer.** Random access no longer requires a tar or cpio container:
  `StreamIndex` is the checkpoint table of one compressed stream,
  `StreamIndexer` lays checkpoints over it (in one pass, or in increments
  with `stop_at` and `resume`), and `StreamReader` decodes any unpacked
  range from the nearest checkpoint. `IndexingEngine` and `ReadEngine` are
  now compositions of these and keep their API. `sync::Stream` and
  `tokio::Stream` wrap a bare `.gz`/`.xz`/`.zst`/`.bz2` file the way
  `Archive` wraps an archive.
- **Live readers.** `StreamReader::seek_forward` retargets a reader at a
  later range without restoring a checkpoint, so sequential range reads
  cost only the new bytes; `compressed_position` says where the caller
  should read next.
- **Codec chains.** `CodecSpec` names a stream's decoding stages in
  packed-to-unpacked order and builds the decompressor: `Copy`, `Deflate`
  (gzip-framed or raw), `Bzip2`, raw `Lzma` (LZMA1), raw `Lzma2`, `Xz`,
  `Zstd`, `Delta`, the BCJ converters for x86, PowerPC, IA-64, ARM,
  ARM Thumb, SPARC, ARM64 and RISC-V, `Bcj2` (7-Zip's four-stream x86
  converter; the caller decodes the CALL, JUMP and range-coder side streams
  whole and hands them over with `set_bcj2_streams`, the main stream flows
  through the chain) and `AesCbc` (AES-256-CBC, behind the new default-on
  `aes` feature; the key is never serialized). Chains checkpoint as a
  whole, including bytes in flight between stages.
- The `Decompressor` trait, every codec and the checkpoint types are
  public API; `lzma` gained a raw LZMA1 stage and `gzip` a raw-deflate
  constructor.

### Fixed

- The gzip decoder reported the end of the stream on the decode call that
  reached the trailer even when part of that call's output was still staged
  inside it, so a `StreamReader` retargeted with `seek_forward` at that
  point served nothing for the rest of the file.

### Changed

- **Checkpoints are exact.** `Decompressor::checkpoint` now returns
  `Option<Checkpoint>`: a checkpoint carries the caller's offsets, and a
  codec that can only resume at block boundaries (deflate, bzip2) answers
  `None` between them instead of returning the last boundary. The indexer
  simply tries again after later steps. Consequence: gzip and bzip2 streams
  no longer accumulate duplicate start checkpoints when a strategy fires
  before the first boundary; a highly compressible gzip stream that fits in
  one deflate block gets exactly one checkpoint, since there is nowhere to
  resume from. bzip2 decoding now returns at each block magic so the
  boundary can be checkpointed before output moves past it.
- **`ArchiveIndex` holds a `StreamIndex`** (`index.stream`) instead of a
  bare checkpoint vector; `checkpoints()` is the accessor. The index format
  version is bumped to 5; indexes built by earlier versions are rejected on
  load and must be rebuilt.
- Filters are ported from XZ Utils' simple filters and delta decoder (0BSD);
  no new C dependency. The `aes` crate is the only dependency added.

## 0.3.0 — 2026-07-15

### Changed

- **xz/LZMA checkpoints shrank by ~500x.** Checkpoints previously
  serialized the LZMA dictionary at its full allocated size — 64 MiB at
  xz preset 9 — including the unwritten zero tail. They now store only the
  live window contents (~130 KB after decoding ~115 KB at preset 9),
  scaling with decoded data instead of dictionary size, which makes
  frequent checkpointing practical. This changes the checkpoint format,
  so **the index format version is bumped to 4**; indexes built by
  earlier versions are rejected on load and must be rebuilt. XZ checkpoint
  size estimation also now accounts for staged output.
- cpio hardlinks are now resolved correctly for the standard newc layout
  (file data stored with the last member of a hardlink set): earlier
  members are emitted as `HardLink` entries pointing at the data-bearing
  path. Previously no cpio hardlinks were ever detected.
- Unknown/corrupt index files, tar headers, and cpio headers are rejected
  with errors instead of risking panics or unbounded allocations (see
  Fixed).

### Fixed

- **gzip: truncated or corrupt deflate streams reported as clean EOF.**
  Inflate failures were mapped to a successful end-of-stream, so corrupt
  gzip archives indexed "successfully" with silently missing data. They
  now surface as decompression errors, including during indexing.
- **Engines could recurse unboundedly on malformed data.** The
  step-recursion in the indexing and read engines had no forward-progress
  guard; a stalled decompressor now produces an error instead of a stack
  overflow. The read engine also no longer drives the decompressor with
  empty input mid-stream.
- **Index entries could reference a checkpoint starting after their data.**
  `ArchiveIndex::checkpoint_for` would then mis-seek. Entries are now
  associated with the latest checkpoint at or before their data offset.
- **`ArchiveIndex::from_bytes` hardened against untrusted input:** bincode
  reads are size-limited (no allocation bombs from corrupt length
  prefixes) and indexes with no checkpoints or out-of-range checkpoint
  references are rejected instead of panicking later.
- **tar parser hardening:** GNU sparse entries (typeflag 'S') are rejected
  instead of silently desynchronizing all subsequent offsets; sizes that
  would overflow block padding are rejected; PAX/long-name metadata sizes
  are capped (no attacker-controlled allocations); PAX records are parsed
  by their length prefix, so values containing newlines or spaces survive
  intact; contiguous files (typeflag '7') index as regular files.
- **cpio parser hardening:** odc headers arriving in small chunks no
  longer cause an arithmetic underflow (sub-format is now detected from
  the magic bytes before sizing the header); namesize and symlink-target
  sizes are capped.
- Read-path performance: the read engine reuses its skip buffer instead of
  allocating 64 KiB per skipped chunk (~80k allocations for a multi-GB
  seek), and the sync/tokio readers hoist their output buffers out of the
  event loop.

## 0.2.0 — 2026-07-14

### Changed

- **zstd decoder: ~5x faster decompression.** Bit reading now uses unaligned
  64-bit loads with a register-resident cache instead of per-bit loops; the
  four Huffman literal streams decode interleaved for instruction-level
  parallelism; sequence decoding and execution are fused with memcpy-based
  match copies (with fixed-size fast paths for short copies); blocks decode
  directly into the shared history buffer, eliminating the staged-output
  copy and per-block window trimming; predefined FSE tables are built once
  and entropy tables are no longer cloned per block.
- **xz/LZMA decoder: ~1.3x faster decompression.** Added a fast path that
  decodes whole LZMA symbols with the range coder held in local registers
  while generous input/output margins remain (the resumable state machine
  still handles buffer boundaries and checkpoint resume); match copies and
  uncompressed LZMA2 chunks now use chunked slice copies through the
  dictionary instead of per-byte pushes through a pending-output queue; the
  XZ layer reuses its LZMA2 scratch buffer across calls.
- **Index format version bumped to 3** (XZ checkpoint state gained a field;
  see below). Indexes built by earlier versions are rejected on load and
  must be rebuilt.

### Fixed

- **xz: checkpoint/restore lost decoded-but-undelivered output.** A
  checkpoint taken while the XZ decompressor still held staged output that
  the caller had not yet read would silently drop those bytes on restore,
  corrupting reads that resumed from such a checkpoint. This could occur
  through the engine as well, since checkpoints are taken right after a
  decompress step and highly compressible data can stage more output than
  one step delivers. The staged output is now included in the checkpoint
  state. Found by new randomized stress tests (`tests/decoder_stress.rs`).

## 0.1.1 — 2026-03-10

### Fixed

- **bzip2: checkpoint offsets drift due to RLE1 byte count mismatch.**
  The bzip2 checkpoint `uncompressed_offset` was computed from a formula
  (`block_index * block_capacity`) that assumed each block holds exactly
  `blockSize100k * 100000 - 19` original bytes. This is wrong because
  bzip2's initial RLE1 step changes the byte count per block, causing
  cumulative drift. Files read via checkpoint restore returned corrupted
  data or content from the wrong offset. Fixed by tracking the
  decompressor's actual output at each block boundary, using a pre-scan
  to split decompression at boundary positions for precise tracking
  without per-byte overhead.

## 0.1.0 — 2026-03-09

Initial release.
