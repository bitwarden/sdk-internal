pub trait BitwardenError {
    /// The name of the error.
    fn variant(&self) -> &'static str;

    /// A human-readable description of the error.
    fn message(&self) -> &'static str;
}
