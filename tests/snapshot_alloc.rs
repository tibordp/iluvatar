//! Taking an index snapshot allocates in proportion to the number of
//! checkpoints and entries, not to the checkpoint data they hold.
#![cfg(feature = "zstandard")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};

use iluvatar::{CompressionFormat, EngineRequest, FixedInterval, IndexingEngine};

/// Counts bytes allocated on threads that switched counting on.
struct Counting;

static ALLOCATED: AtomicU64 = AtomicU64::new(0);

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.with(|c| c.get()) {
            ALLOCATED.fetch_add(layout.size() as u64, Ordering::Relaxed);
        }
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if COUNTING.with(|c| c.get()) {
            ALLOCATED.fetch_add(
                new_size.saturating_sub(layout.size()) as u64,
                Ordering::Relaxed,
            );
        }
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// Bytes `f` allocates on this thread.
fn allocated_by<T>(f: impl FnOnce() -> T) -> (T, u64) {
    let before = ALLOCATED.load(Ordering::Relaxed);
    COUNTING.with(|c| c.set(true));
    let out = f();
    COUNTING.with(|c| c.set(false));
    (out, ALLOCATED.load(Ordering::Relaxed) - before)
}

#[test]
fn zstd_snapshot_allocates_per_checkpoint_not_per_byte() {
    let mut builder = tar::Builder::new(Vec::new());
    let mut rng = 1u64;
    for i in 0..16 {
        let data: Vec<u8> = (0..256 * 1024)
            .map(|_| {
                rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
                (rng >> 33) as u8
            })
            .collect();
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, format!("f{i:02}"), &data[..])
            .unwrap();
    }
    let tar = builder.into_inner().unwrap();
    let data = zstd::encode_all(std::io::Cursor::new(&tar), 3).unwrap();

    let mut engine = IndexingEngine::with_strategy(
        CompressionFormat::Zstd,
        None,
        FixedInterval::new(256 * 1024),
        data.len() as u64,
    )
    .unwrap();
    let mut offset = 0;
    loop {
        match engine.step() {
            EngineRequest::NeedInput if offset < data.len() => {
                let end = (offset + 65536).min(data.len());
                engine.provide_data(&data[offset..end]);
                offset = end;
            }
            EngineRequest::NeedInput => engine.signal_eof(),
            EngineRequest::Done => break,
            EngineRequest::Error(e) => panic!("indexing error: {e}"),
            _ => {}
        }
    }

    let progress = engine.progress();
    assert!(progress.checkpoints_created > 8);
    assert!(progress.checkpoint_data_bytes > 8 * 1024 * 1024);

    let (snapshot, bytes) = allocated_by(|| engine.snapshot_index());
    assert_eq!(snapshot.checkpoints().len(), progress.checkpoints_created);
    // Pointers, entries and the path map: a few KiB here, against
    // megabytes of checkpoint state that a deep copy would duplicate.
    assert!(
        bytes < 64 * 1024,
        "snapshot allocated {bytes} B for {} checkpoints holding {} B",
        progress.checkpoints_created,
        progress.checkpoint_data_bytes
    );
}
