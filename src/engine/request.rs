/// A request from the engine to the caller.
///
/// The engine never performs I/O itself. Instead, it emits these requests
/// to tell the caller what data it needs or what it has produced. The
/// caller drives the engine by calling `step()`, handling the returned
/// request, and calling `step()` again.
///
/// # Handling each variant
///
/// ```no_run
/// # fn example(engine: &mut iluvatar::ReadEngine) {
/// use iluvatar::EngineRequest;
///
/// match engine.step() {
///     EngineRequest::NeedInput => { /* read and call provide_data() */ }
///     EngineRequest::SeekAndRead { offset, len } => { /* seek, read, provide_data() */ }
///     EngineRequest::OutputReady => { /* call read_output() */ }
///     EngineRequest::Done => { /* finished */ }
///     EngineRequest::Error(e) => { /* handle error */ }
/// }
/// # }
/// ```
#[derive(Debug)]
pub enum EngineRequest {
    /// The engine needs more compressed input data.
    ///
    /// The caller should read the next chunk and call `provide_data()`,
    /// or call `signal_eof()` if no more data is available.
    NeedInput,

    /// The engine needs compressed data at a specific position.
    ///
    /// The caller should seek to `offset` in the compressed stream,
    /// read up to `len` bytes, and call `provide_data()`. Only emitted
    /// by [`ReadEngine`](crate::ReadEngine), never by
    /// [`IndexingEngine`](crate::IndexingEngine).
    SeekAndRead {
        /// Byte offset to seek to in the compressed stream.
        offset: u64,
        /// Suggested number of bytes to read.
        len: usize,
    },

    /// The engine has decompressed output data ready.
    ///
    /// The caller should call `read_output()` to consume it. Only emitted
    /// by [`ReadEngine`](crate::ReadEngine).
    OutputReady,

    /// The engine has completed the current operation.
    ///
    /// For [`IndexingEngine`](crate::IndexingEngine), call `finish()` to
    /// get the built index. For [`ReadEngine`](crate::ReadEngine), all
    /// file data has been emitted.
    Done,

    /// An error occurred during decompression or archive parsing.
    Error(crate::error::Error),
}
