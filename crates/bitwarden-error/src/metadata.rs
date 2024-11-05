pub trait AsErrorMetadata {
    fn as_metadata(&self) -> ErrorMetadata;
}

pub struct ErrorMetadata {
    /// The name of the error
    pub name: &'static str,

    /// A human-readable description of the error
    pub message: &'static str,
}
