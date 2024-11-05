pub trait ErrorVariant {
    fn error_variants() -> &'static [&'static str];
    fn error_variant(&self) -> &'static str;
}
