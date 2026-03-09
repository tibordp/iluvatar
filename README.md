# supertar

Efficient random access to files within compressed tar and cpio archives.

supertar builds an index of a compressed archive, including periodic decompressor
state checkpoints, enabling fast random access to any file without decompressing
the entire archive from the beginning.

## Features

- **Multiple archive formats**: tar and cpio (newc, odc), auto-detected
- **Multiple compression formats**: gzip, bzip2, xz, zstd, and uncompressed
- **Pure Rust decompressors**: xz/LZMA2 and zstd are implemented from scratch
  with no C dependencies, including full checkpoint/resume support
- **Sans-I/O core**: The engine never performs I/O itself, making it compatible
  with sync, async, and custom runtimes (e.g. a VFS layer)
- **Persistent index**: Serialize the index to disk and reuse it across sessions
- **Decompression checkpoints**: Periodic snapshots of decompressor state allow
  seeking to nearby positions without full re-decompression
- **Range reads**: Read arbitrary byte ranges within files efficiently by seeking
  to the nearest checkpoint
- **Incremental indexing**: Monitor progress, take snapshots, or cancel early
  and still use the partial index
- **CLI tool**: Browse, list, and extract files from compressed archives

## CLI

Install the CLI with:

```sh
cargo install supertar --features cli
```

### Usage

```sh
# Build an index (stored alongside the archive as .stidx)
supertar index archive.tar.zst

# List archive contents
supertar ls archive.tar.zst
supertar ls -l archive.tar.zst           # long format with permissions, sizes, dates

# Print a file to stdout
supertar cat archive.tar.zst path/to/file.txt
supertar cat archive.tar.zst big.bin --offset 0 --length 1024  # byte range

# Extract a file
supertar cp archive.tar.zst path/to/file.txt ./output/
```

The index is built automatically on first access if no `.stidx` file exists.
Subsequent operations reuse the saved index for instant access.

## Library Quick Start

```rust
use supertar::sync::Archive;
use std::fs::File;

let file = File::open("data.tar.gz")?;
let mut archive = Archive::new(file)?;

// List all entries
for entry in archive.list() {
    println!("{} ({} bytes)", entry.path, entry.size);
}

// Read a file
let contents = archive.read_file("path/to/file.txt")?;

// Read a byte range within a file
let header = archive.read_file_range("big.bin", 0, 1024)?;

// Save the index for next time
std::fs::write("data.tar.gz.idx", archive.index().to_bytes()?)?;
# Ok::<(), supertar::SupertarError>(())
```

## Sans-I/O Usage

For async runtimes, WASM, or custom I/O, drive the engine directly:

```rust
use supertar::{IndexingEngine, EngineRequest, CompressionFormat};

let mut engine = IndexingEngine::new(
    CompressionFormat::Gzip,
    None,        // auto-detect archive format (tar vs cpio)
    1024 * 1024, // checkpoint every 1 MiB of uncompressed data
    file_size,
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
# Ok::<(), supertar::SupertarError>(())
```

## Progress Tracking and Cancellation

```rust
use supertar::sync::Archive;
use std::fs::File;

let mut file = File::open("large.tar.gz")?;
let file_size = file.metadata()?.len();
let index = Archive::build_index_with_progress(
    &mut file,
    file_size,
    1024 * 1024,
    |progress| {
        if let Some(pct) = progress.fraction() {
            println!("{:.1}% - {} entries found", pct * 100.0, progress.entries_found);
        }
        true // return false to cancel
    },
)?;
# Ok::<(), supertar::SupertarError>(())
```

## How It Works

1. **Indexing pass**: Decompress the entire archive once, recording each file's
   path, size, and byte offset in the uncompressed stream. At regular intervals,
   save a snapshot of the decompressor's internal state (a "checkpoint").

2. **Random reads**: To read a file, find the nearest checkpoint before its data
   offset, restore the decompressor to that state, seek in the compressed stream,
   and decompress forward to the target. With 1 MiB checkpoint intervals, at most
   1 MiB of data needs decompressing per read.

3. **Range reads**: For reading a byte range within a large file, the engine
   picks the checkpoint closest to the target offset (not just the file's start),
   minimizing decompression overhead.

## Compression Format Support

| Format | Checkpoint Strategy | Implementation |
|--------|-------------------|----------------|
| gzip   | DEFLATE block boundary | miniz_oxide with `block-boundary` feature |
| bzip2  | Full state snapshot | `bzip2` crate (C binding) |
| xz     | Full state snapshot | Pure Rust LZMA2 decoder (no C dependencies) |
| zstd   | Full state snapshot | Pure Rust decoder (no C dependencies) |
| none   | Trivial offset | Direct byte seeking |

## Archive Format Support

| Format | Variants | Notes |
|--------|----------|-------|
| tar    | ustar, GNU, PAX, V7 | Full support including long names and extended headers |
| cpio   | newc (SVR4), odc (POSIX.1) | Auto-detected from magic bytes |

## Limitations

- **Index must be built first**: The initial indexing pass reads the entire
  archive. Subsequent reads are fast.
- **Memory**: Checkpoint state size varies by format. Gzip checkpoints store a
  32 KiB sliding window. Zstd and xz checkpoints store the full decompressor
  state including window buffers, so index files can be large for these formats.
- **No modification**: This is a read-only library. It cannot create or modify
  archives.
- **Index versioning**: Index format may change between versions. Stored indices
  include a version number and will be rejected if incompatible.

## Feature Flags

All compression formats are enabled by default. Disable what you don't need:

```toml
[dependencies]
supertar = { version = "0.1", default-features = false, features = ["gzip"] }
```

| Feature | Description |
|---------|-------------|
| `gzip` | gzip/DEFLATE support (via miniz_oxide) |
| `bz2` | bzip2 support (via bzip2 crate) |
| `xz` | xz/LZMA2 support (pure Rust) |
| `zstandard` | zstd support (pure Rust) |
| `tokio` | Async API via tokio |
| `cli` | Build the `supertar` CLI binary |

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
