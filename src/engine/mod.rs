//! Sans-I/O engines for indexing and reading archives.
//!
//! The engines in this module never perform I/O. Instead, they communicate
//! with the caller through [`EngineRequest`](request::EngineRequest):
//! the caller calls [`step()`](state_machine::IndexingEngine::step), the
//! engine says what it needs (more data, a seek, etc.), and the caller
//! fulfills the request. This makes them usable with any I/O model.
//!
//! There are two engines:
//!
//! - [`IndexingEngine`](state_machine::IndexingEngine) — Scans an entire
//!   archive to build an [`ArchiveIndex`](crate::index::store::ArchiveIndex).
//! - [`ReadEngine`](state_machine::ReadEngine) — Reads a single file (or byte
//!   range) from an archive using a previously built index.
//!
//! Most users won't need these directly — the [`sync`](crate::sync) and
//! [`tokio`](crate::tokio) modules wrap them with standard I/O. Use the
//! engines when you need control over I/O (e.g. in WASM, a custom VFS,
//! or an async runtime other than tokio).

pub mod progress;
pub mod request;
pub mod state_machine;
