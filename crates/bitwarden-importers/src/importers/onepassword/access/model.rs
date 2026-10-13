//! What a download yields: vaults holding items, each item still in its decrypted 1Password shape.
//!
//! Mapping these onto Bitwarden ciphers is the importer's job and happens elsewhere.

use super::wire::{VaultItemDetails, VaultItemOverview};

/// Everything recovered from an account, including source data that could not be read.
pub struct DownloadedAccount {
    /// Vaults that were opened, possibly with individual skipped items.
    pub vaults: Vec<Vault>,
    /// Vaults that could not be opened.
    pub skipped_vaults: Vec<SkippedVault>,
}

/// A decrypted vault with its items.
pub struct Vault {
    /// The vault's 1Password uuid. The import goes by name.
    #[allow(dead_code)]
    pub id: String,
    /// The vault's display name.
    pub name: String,
    /// Every item in the vault except the trashed ones.
    pub items: Vec<Item>,
    /// Non-trashed items whose encrypted payloads could not be read.
    pub skipped_items: Vec<SkippedItem>,
}

/// A vault that could not be opened.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(serde::Serialize, serde::Deserialize, tsify::Tsify)
)]
pub struct SkippedVault {
    /// The vault's 1Password uuid.
    pub id: String,
    /// The active item count advertised by 1Password, when present.
    pub item_count: Option<u32>,
    /// Why the vault could not be opened.
    pub reason: SkippedReason,
}

/// An item that could not be read from an otherwise accessible vault.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(serde::Serialize, serde::Deserialize, tsify::Tsify)
)]
pub struct SkippedItem {
    /// The item's 1Password uuid.
    pub id: String,
    /// The title, when the overview decrypted before another payload failed.
    pub name: Option<String>,
    /// The item's category, available without decrypting its payloads.
    pub category: ItemCategory,
    /// Why the item could not be read.
    pub reason: SkippedReason,
}

/// A safe, structured reason for leaving source data unimported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(
    feature = "wasm",
    derive(serde::Serialize, serde::Deserialize, tsify::Tsify)
)]
pub enum SkippedReason {
    /// The account does not have the key or permission required to read the data.
    NoAccess,
    /// The source data is encrypted with a scheme the importer does not support.
    Unsupported,
}

/// A decrypted item: its identity plus both payloads exactly as 1Password sends them.
pub struct Item {
    /// The item's 1Password uuid. The server assigns imported ciphers their own.
    #[allow(dead_code)]
    pub id: String,
    /// The item's category, derived from its template id.
    pub category: ItemCategory,
    /// The decrypted `encOverview`: title, websites, tags.
    pub overview: VaultItemOverview,
    /// The decrypted `encDetails`: login fields, sections, note.
    pub details: VaultItemDetails,
}

/// The kind of a vault item, mapped from its template id. The ids are 1Password's standard
/// category template UUIDs; an unrecognized id is preserved as [`ItemCategory::Unknown`] so nothing
/// is lost.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(
    feature = "wasm",
    derive(serde::Serialize, serde::Deserialize, tsify::Tsify)
)]
pub enum ItemCategory {
    /// Template `001`.
    Login,
    /// Template `002`.
    CreditCard,
    /// Template `003`.
    SecureNote,
    /// Template `004`.
    Identity,
    /// Template `005`.
    Password,
    /// Template `006`.
    Document,
    /// Template `100`.
    SoftwareLicense,
    /// Template `101`.
    BankAccount,
    /// Template `102`.
    Database,
    /// Template `103`.
    DriverLicense,
    /// Template `104`.
    OutdoorLicense,
    /// Template `105`.
    Membership,
    /// Template `106`.
    Passport,
    /// Template `107`.
    RewardProgram,
    /// Template `108`.
    SocialSecurityNumber,
    /// Template `109`.
    WirelessRouter,
    /// Template `110`.
    Server,
    /// Template `111`.
    EmailAccount,
    /// Template `112`.
    ApiCredential,
    /// Template `113`.
    MedicalRecord,
    /// Template `114`.
    SshKey,
    /// A template id this crate does not know, kept verbatim.
    Unknown(String),
}

impl ItemCategory {
    /// Maps a 1Password template id to a category. Extends the `TemplateId` handling in
    /// `Client.ConvertVaultItem` to the full standard template set.
    pub(super) fn from_template_id(id: &str) -> ItemCategory {
        match id {
            "001" => ItemCategory::Login,
            "002" => ItemCategory::CreditCard,
            "003" => ItemCategory::SecureNote,
            "004" => ItemCategory::Identity,
            "005" => ItemCategory::Password,
            "006" => ItemCategory::Document,
            "100" => ItemCategory::SoftwareLicense,
            "101" => ItemCategory::BankAccount,
            "102" => ItemCategory::Database,
            "103" => ItemCategory::DriverLicense,
            "104" => ItemCategory::OutdoorLicense,
            "105" => ItemCategory::Membership,
            "106" => ItemCategory::Passport,
            "107" => ItemCategory::RewardProgram,
            "108" => ItemCategory::SocialSecurityNumber,
            "109" => ItemCategory::WirelessRouter,
            "110" => ItemCategory::Server,
            "111" => ItemCategory::EmailAccount,
            "112" => ItemCategory::ApiCredential,
            "113" => ItemCategory::MedicalRecord,
            "114" => ItemCategory::SshKey,
            other => ItemCategory::Unknown(other.to_string()),
        }
    }
}
