use std::io;
use wasm_bindgen_futures::js_sys;

/// A writer that forwards log output to a JavaScript callback function.
pub struct FlightRecorderCallbackWriter {
    callback: js_sys::Function,
}
unsafe impl Send for FlightRecorderCallbackWriter {}
unsafe impl Sync for FlightRecorderCallbackWriter {}

impl FlightRecorderCallbackWriter {
    pub fn new(callback: js_sys::Function) -> Self {
        Self { callback }
    }
}

impl io::Write for FlightRecorderCallbackWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let message = String::from_utf8_lossy(buf);
        let this = wasm_bindgen::JsValue::NULL;
        let js_message = wasm_bindgen::JsValue::from_str(&message);

        self.callback
            .call1(&this, &js_message)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "JavaScript callback failed"))?;

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for FlightRecorderCallbackWriter {
    type Writer = FlightRecorderCallbackWriter;

    fn make_writer(&'a self) -> Self::Writer {
        FlightRecorderCallbackWriter::new(self.callback.clone())
    }

    fn make_writer_for(&'a self, _meta: &tracing::Metadata<'_>) -> Self::Writer {
        FlightRecorderCallbackWriter::new(self.callback.clone())
    }
}
