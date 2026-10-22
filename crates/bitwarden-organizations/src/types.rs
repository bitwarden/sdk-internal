use bitwarden_uuid::uuid_newtype;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

uuid_newtype!(pub OrganizationUserId);
uuid_newtype!(pub ProviderId);

/// The membership status of a user within an organization.
#[derive(PartialEq, Serialize_repr, Deserialize_repr, Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[bitwarden_ffi::wasm_object]
#[repr(i8)]
pub enum OrganizationUserStatusType {
    /// The user's access has been revoked. This may occur at any time from any other status.
    Revoked = -1,
    /// The user has been invited but has not yet accepted.
    Invited = 0,
    /// The user has accepted the invitation but has not yet been confirmed by an admin.
    Accepted = 1,
    /// The user has been confirmed by an admin and has full access.
    Confirmed = 2,
    /// The user has been staged for provisioning but has not yet been invited.
    Staged = 3,
}

/// The role of a user within an organization.
#[derive(PartialEq, Serialize_repr, Deserialize_repr, Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[bitwarden_ffi::wasm_object]
#[repr(u8)]
pub enum OrganizationUserType {
    /// Full administrative control over the organization.
    Owner = 0,
    /// Administrative access with most management capabilities.
    Admin = 1,
    /// Standard organization member.
    User = 2,
    // 3 was Manager, which has been permanently deleted
    /// User with a customized set of permissions as indicated by [`Permissions`].
    Custom = 4,
}

/// The type of provider.
#[derive(PartialEq, Serialize_repr, Deserialize_repr, Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[bitwarden_ffi::wasm_object]
#[repr(u8)]
pub enum ProviderType {
    /// Managed Service Provider - sells and manages its clients' Bitwarden organizations.
    Msp = 0,
    /// Reseller partner - sells Bitwarden to its clients but does not have any administrative
    /// access.
    Reseller = 1,
    /// Business unit provider - used to manage multiple organizations which form part of a single
    /// large enterprise.
    BusinessUnit = 2,
}

/// The method used to decrypt organization member data.
#[derive(PartialEq, Serialize_repr, Deserialize_repr, Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[bitwarden_ffi::wasm_object]
#[repr(u8)]
pub enum MemberDecryptionType {
    /// Decryption using the user's master password.
    MasterPassword = 0,
    /// Decryption via Key Connector.
    KeyConnector = 1,
    /// Decryption via Trusted Device Encryption.
    TrustedDeviceEncryption = 2,
}

/// The subscription tier of an organization.
#[derive(PartialEq, Serialize_repr, Deserialize_repr, Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[bitwarden_ffi::wasm_object]
#[repr(u8)]
pub enum ProductTierType {
    /// Free tier with limited features.
    Free = 0,
    /// Families plan for personal use.
    Families = 1,
    /// Teams plan for small organizations.
    Teams = 2,
    /// Enterprise plan with full features.
    Enterprise = 3,
    /// Starter tier for small teams.
    TeamsStarter = 4,
}

/// Custom administrative permissions for an organization member with the
/// [`OrganizationUserType::Custom`] role.
#[derive(Default, PartialEq, Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
#[serde(rename_all = "camelCase", default)]
pub struct Permissions {
    /// Can view the organization's event logs.
    pub access_event_logs: bool,
    /// Can import and export organization vault data.
    pub access_import_export: bool,
    /// Can access organization reports.
    pub access_reports: bool,
    /// Can create new collections.
    pub create_new_collections: bool,
    /// Can edit any collection, including those they are not assigned to.
    pub edit_any_collection: bool,
    /// Can delete any collection, including those they are not assigned to.
    pub delete_any_collection: bool,
    /// Can manage groups within the organization.
    pub manage_groups: bool,
    /// Can manage SSO configuration.
    pub manage_sso: bool,
    /// Can manage organization policies.
    pub manage_policies: bool,
    /// Can manage organization members.
    pub manage_users: bool,
    /// Can manage the account recovery (password reset) feature.
    pub manage_reset_password: bool,
    /// Can manage SCIM (System for Cross-domain Identity Management) configuration.
    pub manage_scim: bool,
}
