/// A request from the engine to the caller.
///
/// The engine never performs I/O itself. Instead, it emits these requests
/// to tell the caller what data it needs or what it has produced.
#[derive(Debug)]
pub enum EngineRequest {
    /// The engine needs more compressed input data.
    /// The caller should read the next chunk of compressed data
    /// and call `provide_data()`.
    NeedInput,

    /// The engine needs compressed data at a specific position.
    /// The caller should seek to `offset` in the compressed stream,
    /// read up to `len` bytes, and call `provide_data()`.
    SeekAndRead { offset: u64, len: usize },

    /// The engine has decompressed output data ready.
    /// The caller should call `read_output()` to consume it.
    OutputReady,

    /// The engine has completed the current operation.
    Done,

    /// An error occurred.
    Error(crate::error::Error),
}
