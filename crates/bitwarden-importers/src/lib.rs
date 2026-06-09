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
mod pipeline;

/// Destination options for a vault import.
///
/// `organization_id` selects the destination: `None` imports into the user's personal vault (groups
/// become personal folders), `Some` imports into that organization (ciphers are encrypted with the
/// org key). The `target_*` fields nest the import under an existing folder (personal) or
/// collection (organization), mirroring the client's import-target behavior. `restricted_types` are
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
    pub target_folder_id: Option<FolderId>,
    pub target_folder_name: Option<String>,
    pub target_collection_id: Option<CollectionId>,
    pub target_collection_name: Option<String>,
    // `VaultCipherType` is the wasm-bindgen enum exported as `CipherType`; pin the TS name so
    // tsify doesn't emit the Rust alias.
    #[cfg_attr(feature = "wasm", tsify(type = "CipherType[]"))]
    pub restricted_types: Vec<VaultCipherType>,
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
