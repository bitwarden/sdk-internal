pub trait ErrorVariant {
    fn error_variant(&self) -> &'static str;
}
