//! Native 1Password model: Vault, Item, Field and friends.
//!
//! The model stays faithful to 1Password rather than Bitwarden; mapping it onto Bitwarden ciphers
//! is the importer's job. `parse` builds these from the wire DTOs.

use std::fmt;

/// A decrypted vault with its items.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub fn from_template_id(id: &str) -> ItemCategory {
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

impl fmt::Display for ItemCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            ItemCategory::Login => "Login",
            ItemCategory::CreditCard => "Credit Card",
            ItemCategory::SecureNote => "Secure Note",
            ItemCategory::Identity => "Identity",
            ItemCategory::Password => "Password",
            ItemCategory::Document => "Document",
            ItemCategory::SoftwareLicense => "Software License",
            ItemCategory::BankAccount => "Bank Account",
            ItemCategory::Database => "Database",
            ItemCategory::DriverLicense => "Driver License",
            ItemCategory::OutdoorLicense => "Outdoor License",
            ItemCategory::Membership => "Membership",
            ItemCategory::Passport => "Passport",
            ItemCategory::RewardProgram => "Reward Program",
            ItemCategory::SocialSecurityNumber => "Social Security Number",
            ItemCategory::WirelessRouter => "Wireless Router",
            ItemCategory::Server => "Server",
            ItemCategory::EmailAccount => "Email Account",
            ItemCategory::ApiCredential => "API Credential",
            ItemCategory::MedicalRecord => "Medical Record",
            ItemCategory::SshKey => "SSH Key",
            ItemCategory::Unknown(id) => return write!(f, "Unknown({id})"),
        };
        f.write_str(name)
    }
}

/// A decrypted vault item in the native 1Password model.
///
/// Nothing is dropped: whatever has no dedicated home stays in [`Item::fields`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// The item's 1Password uuid.
    pub id: String,
    /// The item's category, derived from its template id.
    pub category: ItemCategory,
    /// The item's title.
    pub title: String,
    /// The subtitle 1Password shows under the title, usually the username.
    pub additional_info: String,
    /// The item's plain-text note.
    pub note: String,
    /// The username, for login-style categories only.
    pub username: String,
    /// The password, for login-style categories only.
    pub password: String,
    /// The primary website, for login-style categories only.
    pub url: String,
    /// Every website associated with the item.
    pub urls: Vec<Url>,
    /// Every one-time-password field found on the item.
    pub otps: Vec<Otp>,
    /// Every section field, flattened with its section and metadata preserved.
    pub fields: Vec<Field>,
    /// The raw SSH key, for SSH key items only.
    pub ssh_key: Option<SshKey>,
    /// The item's tags, which 1Password also uses to record how an item was imported.
    pub tags: Vec<String>,
    /// Superseded passwords, oldest first as the server sends them.
    pub password_history: Vec<PastPassword>,
}

/// A password the item used before the current one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PastPassword {
    /// The old password.
    pub password: String,
    /// When it was replaced, as a unix timestamp, or 0 when the server omits it.
    pub changed_at: i64,
}

/// A flattened section field with all of its metadata preserved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    /// 1Password's internal field id.
    pub id: String,
    /// The field's display label.
    pub label: String,
    /// The field's value, rendered as text.
    pub value: String,
    /// 1Password's field kind, such as `string`, `concealed` or `menu`.
    pub kind: String,
    /// The title of the section the field belongs to, empty for the unnamed section.
    pub section: String,
    /// Whether 1Password marks the field as guarded, meaning it holds a secret.
    pub guarded: bool,
}

/// A website associated with an item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    /// The URL's label, empty when unset.
    pub label: String,
    /// The URL itself.
    pub value: String,
}

/// A one-time-password field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Otp {
    /// The field's display label.
    pub label: String,
    /// The TOTP secret, usually an `otpauth://` URI or a bare base32 seed.
    pub secret: String,
    /// The title of the section the field belongs to.
    pub section: String,
}

/// A raw SSH key, exactly as 1Password stores it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshKey {
    /// The private key in whichever format 1Password stored it.
    pub private_key: String,
    /// The public key in OpenSSH format.
    pub public_key: String,
    /// The key's fingerprint.
    pub fingerprint: String,
    /// The key type, such as `ed25519` or `rsa-4096`.
    pub key_type: String,
}
