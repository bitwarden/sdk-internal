use darling::FromMeta;

#[derive(FromMeta)]
pub(crate) struct BitwardenErrorArgs {
    #[darling(flatten)]
    pub error_type: BitwardenErrorType,

    #[darling(default)]
    pub export_as: Option<String>,
}

#[derive(FromMeta)]
#[darling(rename_all = "snake_case")]
pub(crate) enum BitwardenErrorType {
    /// The error is going to be converted into a string using the `ToString` trait
    Basic,

    /// The error is going to be converted into a flat error using the `FlatError` trait
    Flat,

    /// The entire error stack is going to be made available using `serde`
    Full,
}
