#![doc = include_str!("../README.md")]

use std::sync::OnceLock;

#[expect(clippy::type_complexity)]
static ERROR_TO_UNIFFI_ERROR: OnceLock<
    Box<dyn Fn(Box<dyn std::error::Error + Send + Sync>) -> anyhow::Error + Send + Sync + 'static>,
> = OnceLock::new();

pub use anyhow::Error;

/// Configure an error converter to convert errors in calls to
/// [`uniffi::custom_type!`](https://docs.rs/uniffi/latest/uniffi/macro.custom_type.html) into the
/// main error of the application (`bitwarden_uniffi::error::BitwardenError). This is needed because
/// if the errors don't match, Uniffi will panic instead of returning an error. This needs to be
/// called by the `bitwarden_uniffi` crate before any other Uniffi code is run.
pub fn set_error_to_uniffi_error<F>(f: F)
where
    F: Fn(Box<dyn std::error::Error + Send + Sync>) -> anyhow::Error + Send + Sync + 'static,
{
    let _ = ERROR_TO_UNIFFI_ERROR.set(Box::new(f));
}

fn convert_error<E: std::error::Error + Send + Sync + 'static>(error: E) -> anyhow::Error {
    if let Some(f) = ERROR_TO_UNIFFI_ERROR.get() {
        f(Box::new(error))
    } else {
        anyhow::Error::new(error)
    }
}

/// Convert a `Result` into one that will not cause a panic when called inside
/// [`uniffi::custom_type!`](https://docs.rs/uniffi/latest/uniffi/macro.custom_type.html). It is
/// required that all the results created inside a `custom_type!` are converted using this function.
pub fn convert_result<T, E: std::error::Error + Send + Sync + 'static>(
    result: Result<T, E>,
) -> Result<T, anyhow::Error> {
    result.map_err(|e| convert_error(e))
}
