# iluvatar

Read individual files from compressed tar and cpio archives without
decompressing the whole thing.

iluvatar works by making an indexing pass over the compressed archive,
recording each file's path, size, and byte offset in the decompressed stream.
At configurable intervals it snapshots the decompressor's internal state (a
"checkpoint"). Later, to read a single file, it restores the nearest
checkpoint, seeks in the compressed stream, and decompresses forward to the
target — typically a small amount of data regardless of archive size.

## Library Usage

```rust
use iluvatar::sync::Archive;
use std::fs::File;

let file = File::open("data.tar.gz")?;
let mut archive = Archive::new(file)?;

for entry in archive.list() {
    println!("{} ({} bytes)", entry.path, entry.size);
}

let contents = archive.read_file("path/to/file.txt")?;

// Read just the first 1 KiB of a large file without decompressing all of it
let header = archive.read_file_range("big.bin", 0, 1024)?;

// Save the index for next time (avoids re-scanning the archive)
std::fs::write("data.tar.gz.idx", archive.index().to_bytes()?)?;
# Ok::<(), iluvatar::Error>(())
```

### Sans-I/O engine

The library core is a sans-I/O state machine — it never calls `read()` or
`seek()` itself, so you can plug it into tokio, WASM, a VFS, or anything else:

```rust
use iluvatar::{IndexingEngine, EngineRequest, CompressionFormat};

let mut engine = IndexingEngine::new(
    CompressionFormat::Gzip,
    None,      // auto-detect archive format (tar vs cpio)
    file_size, // used for progress reporting
)?;

loop {
    match engine.step() {
        EngineRequest::NeedInput => {
            let data = read_some_bytes(); // your I/O
            if data.is_empty() {
                engine.signal_eof();
            } else {
                engine.provide_data(&data);
            }
        }
        EngineRequest::Done => break,
        EngineRequest::Error(e) => return Err(e),
        _ => {}
    }
}

let index = engine.finish();
// Use index with ReadEngine to read individual files
# Ok::<(), iluvatar::Error>(())
```

### Async (tokio)

```rust,ignore
use iluvatar::tokio::Archive;

let file = tokio::fs::File::open("data.tar.zst").await?;
let mut archive = Archive::new(file).await?;
let data = archive.read_file("some/path").await?;
```

### Checkpoint strategies

By default, checkpoint intervals are tuned per compression format (1 MiB for
bzip2, 16 MiB for gzip, 64 MiB for zstd/xz) to balance seek speed against
index size. You can override this with a custom strategy:

```rust
use iluvatar::sync::Archive;
use iluvatar::{FixedInterval, Budget, BudgetRatio};
use std::fs::File;

// Fixed interval: checkpoint every 8 MiB of decompressed data
let file = File::open("data.tar.gz")?;
let archive = Archive::with_strategy(file, FixedInterval::new(8 * 1024 * 1024))?;

// Budget: keep total checkpoint data under ~10 MiB
let file = File::open("data.tar.zst")?;
let archive = Archive::with_strategy(file, Budget::new(10 * 1024 * 1024))?;

// BudgetRatio: keep the index under ~5% of the archive size
let file = File::open("data.tar.xz")?;
let archive = Archive::with_strategy(file, BudgetRatio::new(0.05))?;
# Ok::<(), iluvatar::Error>(())
```

You can also implement the `CheckpointStrategy` trait for fully custom logic.

### Progress tracking

```rust
use iluvatar::sync::Archive;
use std::fs::File;

let mut file = File::open("large.tar.gz")?;
let file_size = file.metadata()?.len();
let index = Archive::build_index_with_progress(
    &mut file,
    file_size,
    |progress| {
        if let Some(pct) = progress.fraction() {
            println!("{:.1}% - {} entries found", pct * 100.0, progress.entries_found);
        }
        true // return false to cancel early and get a partial index
    },
)?;
# Ok::<(), iluvatar::Error>(())
```

## How it works

1. **Indexing pass** — Decompress the entire archive once, recording each
   file's metadata and byte offset. Periodically snapshot the decompressor
   state into a "checkpoint".

2. **Random reads** — To read a file, find the nearest checkpoint before its
   data offset, restore the decompressor to that saved state, seek to the
   corresponding position in the compressed stream, and decompress forward.
   The checkpoint interval controls the maximum decompression needed per read.

3. **Range reads** — When reading a byte range within a large file, the engine
   picks the checkpoint closest to the target offset (not the file's start),
   so reading byte 9 GB of a 10 GB file doesn't decompress the first 9 GB.

## Supported formats

**Archive formats:**

| Format | Variants |
|--------|----------|
| tar    | ustar, GNU, PAX, V7 (including long name extensions) |
| cpio   | newc (SVR4), odc (POSIX.1) |

**Compression formats:**

| Format | Checkpoint method | Implementation |
|--------|-------------------|----------------|
| gzip   | DEFLATE block boundary | `miniz_oxide` with `block-boundary` feature |
| bzip2  | Full state snapshot | `bzip2` crate (C binding) |
| xz     | Full state snapshot | Built-in LZMA2 decoder |
| zstd   | Full state snapshot | Built-in decoder |
| none   | Trivial byte offset | Direct seeking |

The xz and zstd decompressors are built-in rather than wrapping C libraries,
because checkpoint/resume requires access to the full decompressor state,
which C library wrappers don't expose.

## Limitations

- **The initial indexing pass reads the entire archive.** There's no way around
  this — you have to decompress everything once to find out what's in the
  archive. Subsequent reads are fast.
- **Index files can be large.** Gzip checkpoints store a 32 KiB window per
  checkpoint; zstd and xz store the full decompressor state including
  dictionary buffers, which can be several hundred KiB per checkpoint. The
  format-aware defaults (16–64 MiB intervals) keep this reasonable, but very
  large archives will still produce sizable indices. Use `Budget` or
  `BudgetRatio` strategies to cap index size.
- **Read-only.** This library cannot create or modify archives.
- **Index format is not stable.** Stored indices include a version number and
  will be rejected if built by an incompatible version. Regenerate them when
  you upgrade.
- **Bzip2 requires a C compiler.** The bzip2 decompressor wraps `libbz2`.
  The other formats are all Rust-only.

## Feature flags

All compression formats are enabled by default. Disable what you don't need:

```toml
[dependencies]
iluvatar = { version = "0.1", default-features = false, features = ["gzip"] }
```

| Feature | Description |
|---------|-------------|
| `gzip` | gzip/DEFLATE support (requires `miniz_oxide`) |
| `bz2` | bzip2 support (requires `bzip2` crate, C binding) |
| `xz` | xz/LZMA2 support |
| `zstandard` | zstd support |
| `tokio` | Async API via tokio |
| `cli` | CLI binary (demo/utility, not the main focus) |

## CLI

A small CLI is included for quick inspection of archives. It's a thin wrapper
around the library, not a production tool.

```sh
cargo install iluvatar --features cli

iluvatar index archive.tar.zst      # build a .stidx index file
iluvatar ls -l archive.tar.zst      # list contents
iluvatar cat archive.tar.zst path/to/file.txt
iluvatar cp archive.tar.zst path/to/file.txt ./output/
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
