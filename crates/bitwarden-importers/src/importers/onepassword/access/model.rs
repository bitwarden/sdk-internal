//! What a download yields: vaults holding items, each item still in its decrypted 1Password shape.
//!
//! Mapping these onto Bitwarden ciphers is the importer's job and happens elsewhere.

use super::wire::{VaultItemDetails, VaultItemOverview};

/// A decrypted vault with its items.
pub struct Vault {
    /// The vault's 1Password uuid.
    pub id: String,
    /// The vault's display name.
    pub name: String,
    /// The vault's description, empty when unset.
    pub description: String,
    /// Every item in the vault except the trashed ones.
    pub items: Vec<Item>,
}

/// A decrypted item: its identity plus both payloads exactly as 1Password sends them.
pub struct Item {
    /// The item's 1Password uuid.
    pub id: String,
    /// The item's category, derived from its template id.
    pub category: ItemCategory,
    /// The decrypted `encOverview`: title, subtitle, websites, tags.
    pub overview: VaultItemOverview,
    /// The decrypted `encDetails`: login fields, sections, note, password history.
    pub details: VaultItemDetails,
}

/// The kind of a vault item, mapped from its template id. The ids are 1Password's standard
/// category template UUIDs; an unrecognized id is preserved as [`ItemCategory::Unknown`] so nothing
/// is lost.
#[derive(Debug, Clone, PartialEq, Eq)]
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
