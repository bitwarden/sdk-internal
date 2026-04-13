#[derive(Clone)]
pub struct GlobalClient {
    // Global state registry...
}

impl GlobalClient {
    /// Returns a reference to the global client instance.
    pub fn new() -> Self {
        Self {}
    }
}
