#![doc = include_str!("../README.md")]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
#[cfg(feature = "uniffi")]
mod uniffi_support;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
#[cfg(feature = "wasm")]
use tsify::Tsify;
use uuid::Uuid;
use wasm_bindgen::prelude::wasm_bindgen;

/// The membership status of a user within an organization.
#[derive(PartialEq, Serialize_repr, Deserialize_repr, Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
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
}

/// The role of a user within an organization.
#[derive(PartialEq, Serialize_repr, Deserialize_repr, Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[repr(u8)]
pub enum OrganizationUserType {
    /// Full administrative control over the organization.
    Owner = 0,
    /// Administrative access with most management capabilities.
    Admin = 1,
    /// Standard organization member.
    User = 2,
    // 3 was Manager, which has been permanently deleted
    /// User with a customized set of permissions as indicated by
    /// [`ProfileOrganization::permissions`].
    Custom = 4,
}

/// The type of provider.
#[derive(Serialize_repr, Deserialize_repr, Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
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
#[derive(Serialize_repr, Deserialize_repr, Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
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
#[derive(Serialize_repr, Deserialize_repr, Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
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
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
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

/// Organization membership details from the user's profile sync.
///
/// Contains the full set of entitlements, plan features, and metadata for a single
/// organization that the current user belongs to.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct ProfileOrganization {
    /// Unique identifier for the organization.
    pub id: Uuid,
    /// Display name of the organization.
    pub name: String,
    /// The user's membership status in the organization.
    pub status: OrganizationUserStatusType,
    /// The user's role in the organization.
    pub r#type: OrganizationUserType,
    /// Whether the organization is currently enabled.
    pub enabled: bool,
    /// Whether the organization has access to policies features.
    pub use_policies: bool,
    /// Whether the organization has access to groups features.
    pub use_groups: bool,
    /// Whether the organization has access to directory sync features.
    pub use_directory: bool,
    /// Whether the organization has access to event logging features.
    pub use_events: bool,
    /// Whether the organization can enforce TOTP for members.
    pub use_totp: bool,
    /// Whether the organization has access to two-factor authentication features.
    pub use_2fa: bool,
    /// Whether the organization has access to the Bitwarden Public API.
    pub use_api: bool,
    /// Whether the organization has access to SSO features.
    pub use_sso: bool,
    /// Whether the organization can manage verified domains.
    pub use_organization_domains: bool,
    /// Whether the organization uses Key Connector for decryption.
    pub use_key_connector: bool,
    /// Whether the organization has access to SCIM provisioning.
    pub use_scim: bool,
    /// Whether the organization can use the [`OrganizationUserType::Custom`] role.
    pub use_custom_permissions: bool,
    /// Whether the organization has access to the account recovery (admin password reset) feature.
    pub use_reset_password: bool,
    /// Whether the organization has access to Secrets Manager.
    pub use_secrets_manager: bool,
    /// Whether the organization has access to Password Manager.
    pub use_password_manager: bool,
    /// Whether the organization can use the activate autofill policy.
    pub use_activate_autofill_policy: bool,
    /// Whether the organization can automatically confirm new members without manual admin
    /// approval.
    pub use_automatic_user_confirmation: bool,
    /// Whether the organization can create a license file for a self-hosted instance.
    pub self_host: bool,
    /// Whether organization members receive premium features.
    pub users_get_premium: bool,
    /// The number of licensed seats for the organization.
    pub seats: Option<u32>,
    /// The maximum number of collections the organization can create.
    pub max_collections: Option<u32>,
    /// The maximum encrypted storage in gigabytes, if limited.
    pub max_storage_gb: Option<u32>,
    /// Whether the current user's account is bound to this organization via SSO.
    pub sso_bound: bool,
    /// The organization's SSO identifier.
    pub identifier: Option<String>,
    /// The current user's custom permissions, relevant when [`OrganizationUserType::Custom`] is
    /// the user's `type`.
    pub permissions: Permissions,
    /// Whether the current user is enrolled in account recovery for this organization.
    pub reset_password_enrolled: bool,
    /// The current user's personal user ID.
    pub user_id: Option<Uuid>,
    /// The current user's organization membership ID.
    pub organization_user_id: Option<Uuid>,
    /// Whether the organization has both a public and private key configured.
    pub has_public_and_private_keys: bool,
    /// The ID of the provider managing this organization, if any.
    pub provider_id: Option<Uuid>,
    /// The name of the provider managing this organization, if any.
    pub provider_name: Option<String>,
    /// The type of provider managing this organization, if any.
    pub provider_type: Option<ProviderType>,
    /// Whether the current user accesses this organization through a provider.
    pub is_provider_user: bool,
    /// Whether the current user is a direct member of this organization (as opposed to
    /// provider-only access).
    pub is_member: bool,
    /// The friendly name of a pending families sponsorship, if any.
    pub family_sponsorship_friendly_name: Option<String>,
    /// Whether the organization can sponsor a families plan for the current user.
    pub family_sponsorship_available: bool,
    /// The subscription tier of the organization.
    pub product_tier_type: ProductTierType,
    /// Whether Key Connector is enabled for this organization.
    pub key_connector_enabled: bool,
    /// The URL of the Key Connector service, if enabled.
    pub key_connector_url: Option<String>,
    /// The date the families sponsorship was last synced, if applicable.
    pub family_sponsorship_last_sync_date: Option<DateTime<Utc>>,
    /// The date the families sponsorship expires, if applicable.
    pub family_sponsorship_valid_until: Option<DateTime<Utc>>,
    /// Whether the families sponsorship is scheduled for deletion.
    pub family_sponsorship_to_delete: Option<bool>,
    /// Whether the current user has access to Secrets Manager for this organization.
    pub access_secrets_manager: bool,
    /// Whether collection creation is restricted to owners and admins only.
    ///
    /// When `false`, any member can create collections and automatically receives manage
    /// permissions over collections they create.
    pub limit_collection_creation: bool,
    /// Whether collection deletion is restricted to owners and admins only.
    ///
    /// When `true`, regular users cannot delete collections that they manage.
    pub limit_collection_deletion: bool,
    /// Whether item deletion is restricted to members with the Manage collection permission.
    ///
    /// When `false`, members with Edit permission can also delete items within their collections.
    pub limit_item_deletion: bool,
    /// Whether owners and admins have implicit manage permissions over all collections.
    ///
    /// When `true`, owners and admins can alter items, groups, and permissions across all
    /// collections without requiring explicit collection assignments.
    /// When `false`, admins can only access collections where they have been explicitly assigned.
    pub allow_admin_access_to_all_collection_items: bool,
    /// Whether the current user's account is managed by this organization.
    pub user_is_managed_by_organization: bool,
    /// Whether the organization has access to Access Intelligence features.
    pub use_access_intelligence: bool,
    /// Whether the organization can sponsor families plans for members (Families For Enterprises).
    pub use_admin_sponsored_families: bool,
    /// Whether Secrets Manager ads are disabled for users.
    #[serde(rename = "useDisableSMAdsForUsers")]
    pub use_disable_sm_ads_for_users: bool,
    /// Whether the organization's Families For Enterprises sponsorship was initiated by an admin.
    pub is_admin_initiated: bool,
    /// Whether SSO login is currently enabled for this organization.
    pub sso_enabled: bool,
    /// The decryption type used for SSO members, if SSO is enabled.
    pub sso_member_decryption_type: Option<MemberDecryptionType>,
    /// Whether the organization has access to phishing blocker features.
    pub use_phishing_blocker: bool,
    /// Whether the organization has access to the My Items collection feature.
    /// This allows users to store personal items in the organization vault
    /// if the Centralize Organization Ownership policy is enabled.
    pub use_my_items: bool,
}

impl Default for ProfileOrganization {
    fn default() -> Self {
        ProfileOrganization {
            id: Uuid::nil(),
            name: String::new(),
            status: OrganizationUserStatusType::Confirmed,
            r#type: OrganizationUserType::User,
            enabled: true,
            use_policies: false,
            use_groups: false,
            use_directory: false,
            use_events: false,
            use_totp: false,
            use_2fa: false,
            use_api: false,
            use_sso: false,
            use_organization_domains: false,
            use_key_connector: false,
            use_scim: false,
            use_custom_permissions: false,
            use_reset_password: false,
            use_secrets_manager: false,
            use_password_manager: false,
            use_activate_autofill_policy: false,
            use_automatic_user_confirmation: false,
            self_host: false,
            users_get_premium: false,
            seats: Some(10),
            max_collections: None,
            max_storage_gb: None,
            sso_bound: false,
            identifier: None,
            permissions: Permissions::default(),
            reset_password_enrolled: false,
            user_id: None,
            organization_user_id: None,
            has_public_and_private_keys: false,
            provider_id: None,
            provider_name: None,
            provider_type: None,
            is_provider_user: false,
            is_member: true,
            family_sponsorship_friendly_name: None,
            family_sponsorship_available: false,
            product_tier_type: ProductTierType::Free,
            key_connector_enabled: false,
            key_connector_url: None,
            family_sponsorship_last_sync_date: None,
            family_sponsorship_valid_until: None,
            family_sponsorship_to_delete: None,
            access_secrets_manager: false,
            limit_collection_creation: false,
            limit_collection_deletion: false,
            limit_item_deletion: false,
            allow_admin_access_to_all_collection_items: false,
            user_is_managed_by_organization: false,
            use_access_intelligence: false,
            use_admin_sponsored_families: false,
            use_disable_sm_ads_for_users: false,
            is_admin_initiated: false,
            sso_enabled: false,
            sso_member_decryption_type: None,
            use_phishing_blocker: false,
            use_my_items: false,
        }
    }
}
