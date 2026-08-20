#![doc = include_str!("../README.md")]

use bitwarden_collections::collection::CollectionId;
use bitwarden_core::OrganizationId;
use bitwarden_vault::{CipherType as VaultCipherType, FolderId};

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
#[cfg(feature = "uniffi")]
mod uniffi_support;

mod error;
pub use error::ImportError;
mod import;
mod importer_client;
pub use importer_client::{ImporterClient, ImporterClientExt};
mod importers;
pub use importers::keeper;
mod pipeline;

/// Destination options for a vault import.
///
/// `organization_id` selects the destination: `None` imports into the user's personal vault (groups
/// become personal folders), `Some` imports into that organization (ciphers are encrypted with the
/// org key). `target_folder` (personal) and `target_collection` (organization) nest the import
/// under an existing destination, mirroring the client's import-target behavior; each carries both
/// its id and name together so a half-specified target can't be expressed. `restricted_types` are
/// dropped before submission.
#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(serde::Serialize, serde::Deserialize, tsify::Tsify),
    tsify(from_wasm_abi)
)]
pub struct ImportOptions {
    pub organization_id: Option<OrganizationId>,
    pub target_folder: Option<ImportTargetFolder>,
    pub target_collection: Option<ImportTargetCollection>,
    // `VaultCipherType` is the wasm-bindgen enum exported as `CipherType`; pin the TS name so
    // tsify doesn't emit the Rust alias.
    #[cfg_attr(feature = "wasm", tsify(type = "CipherType[]"))]
    pub restricted_types: Vec<VaultCipherType>,
}

/// An existing personal folder to nest a personal import under.
#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(serde::Serialize, serde::Deserialize, tsify::Tsify),
    tsify(from_wasm_abi)
)]
pub struct ImportTargetFolder {
    pub id: FolderId,
    pub name: String,
}

/// An existing organization collection to assign an org import to.
#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(serde::Serialize, serde::Deserialize, tsify::Tsify),
    tsify(from_wasm_abi)
)]
pub struct ImportTargetCollection {
    pub id: CollectionId,
    pub name: String,
}

/// Counts of what an import submitted to the server, broken down by cipher type so the client can
/// render its per-type result table.
#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(serde::Serialize, serde::Deserialize, tsify::Tsify),
    tsify(into_wasm_abi)
)]
pub struct ImportSummary {
    pub ciphers: Vec<CipherTypeCount>,
    pub folders: u32,
    pub collections: u32,
}

/// Number of imported ciphers of a given type.
#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(serde::Serialize, serde::Deserialize, tsify::Tsify),
    tsify(into_wasm_abi)
)]
pub struct CipherTypeCount {
    #[cfg_attr(feature = "wasm", tsify(type = "CipherType"))]
    pub r#type: VaultCipherType,
    pub count: u32,
}
