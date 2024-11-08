pub trait FlatError {
    fn error_variant(&self) -> &'static str;
}
