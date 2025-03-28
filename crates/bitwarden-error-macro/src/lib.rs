#![doc = include_str!("../README.md")]

mod args;
mod attribute;
mod basic;
mod flat;
mod full;

/// A procedural macro for generating error types with customizable serialization behavior.
///
/// # Attributes
///
/// ## Error type
///
/// - `basic`: The error is converted into a string using the `ToString` trait.
/// - `flat`: The error is converted into a flat structure using the `FlatError` trait.
/// - `full`: The entire error stack is made available using `serde`.
///
/// ## Export as
///
/// `export_as`: The name of the exported TypeScript type. If not provided, the name of the Rust
/// type is used. Note: This attribute is only available when using the `basic` and `flat` error
/// types.
///
/// # Examples
///
/// ## Basic
/// Using the `basic` error type:
///
/// ```rust
/// use bitwarden_error::bitwarden_error;
/// use thiserror::Error;
///
/// #[derive(Debug, Error)]
/// #[bitwarden_error(basic)]
/// enum MyError {
///     #[error("Not found")]
///     NotFound,
///     #[error("Permission denied")]
///     PermissionDenied,
/// }
/// ```
///
/// will generate the following TypeScript definition:
///
/// ```typescript
/// export interface MyError extends Error {
///    name: "MyError";
/// }
/// ```
///
/// ## Flat
///
/// Using the `flat` error type:
///
/// ```rust
/// use bitwarden_error::bitwarden_error;
/// use thiserror::Error;
///
/// #[derive(Debug, Error)]
/// #[bitwarden_error(flat)]
/// enum MyError {
///     #[error("Not found")]
///     NotFound,
///     #[error("Permission denied")]
///     PermissionDenied,
/// }
/// ```
///
/// will generate the following TypeScript definition:
///
/// ```typescript
/// export interface MyError extends Error {
///   name: "MyError";
///  variant: "NotFound" | "PermissionDenied";
/// }
/// ```
///
/// Using the `full` error type:
///
/// ```rust
/// use bitwarden_error::bitwarden_error;
/// use serde::Serialize;
/// use thiserror::Error;
///
/// #[bitwarden_error(full)]
/// #[derive(Debug, Error)]
/// #[error("Vault is locked")]
/// struct VaultLocked;
///
/// #[derive(Debug, Serialize)]
/// struct ExternalError;
///
/// #[bitwarden_error(full)]
/// #[derive(Debug, Error)]
/// enum MyError {
///     #[error(transparent)]
///     VaultLocked(#[from] VaultLocked),
///     #[error("External error")]
///     ExternalError(ExternalError),
/// }
/// ```
///
/// will use tsify_next::Tsify to generate roughly the following TypeScript definition:
///
/// ```typescript
/// export type CryptoError =
///   | { MissingFieldError: MissingFieldError }
///   | { VaultLocked: VaultLocked };
///
/// export interface VaultLocked { }
/// ```
///
/// All the general interopability rules apply such as external types needing to be defined as
/// custom types.
#[proc_macro_attribute]
pub fn bitwarden_error(
    args: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    attribute::bitwarden_error(args, item)
}
