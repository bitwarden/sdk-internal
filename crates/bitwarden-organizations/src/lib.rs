#![doc = include_str!("../README.md")]
#![allow(missing_docs)]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
#[cfg(feature = "uniffi")]
mod uniffi_support;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use uuid::Uuid;

#[derive(PartialEq, Serialize_repr, Deserialize_repr, Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[repr(i8)]
pub enum OrganizationUserStatusType {
    Revoked = -1,
    Invited = 0,
    Accepted = 1,
    Confirmed = 2,
}

#[derive(PartialEq, Serialize_repr, Deserialize_repr, Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[repr(u8)]
pub enum OrganizationUserType {
    Owner = 0,
    Admin = 1,
    User = 2,
    // 3 was Manager, which has been permanently deleted
    Custom = 4,
}

#[derive(Serialize_repr, Deserialize_repr, Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[repr(u8)]
pub enum ProviderType {
    Msp = 0,
    Reseller = 1,
    BusinessUnit = 2,
}

#[derive(Serialize_repr, Deserialize_repr, Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[repr(u8)]
pub enum MemberDecryptionType {
    MasterPassword = 0,
    KeyConnector = 1,
    TrustedDeviceEncryption = 2,
}

#[derive(Serialize_repr, Deserialize_repr, Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[repr(u8)]
pub enum ProductTierType {
    Free = 0,
    Families = 1,
    Teams = 2,
    Enterprise = 3,
    TeamsStarter = 4,
}

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(rename_all = "camelCase", default)]
pub struct Permissions {
    pub access_event_logs: bool,
    pub access_import_export: bool,
    pub access_reports: bool,
    pub create_new_collections: bool,
    pub edit_any_collection: bool,
    pub delete_any_collection: bool,
    pub manage_ciphers: bool,
    pub manage_groups: bool,
    pub manage_sso: bool,
    pub manage_policies: bool,
    pub manage_users: bool,
    pub manage_reset_password: bool,
    pub manage_scim: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct ProfileOrganization {
    pub id: Uuid,
    pub name: String,
    pub status: OrganizationUserStatusType,
    pub r#type: OrganizationUserType,
    pub enabled: bool,
    pub use_policies: bool,
    pub use_groups: bool,
    pub use_directory: bool,
    pub use_events: bool,
    pub use_totp: bool,
    pub use_2fa: bool,
    pub use_api: bool,
    pub use_sso: bool,
    pub use_organization_domains: bool,
    pub use_key_connector: bool,
    pub use_scim: bool,
    pub use_custom_permissions: bool,
    pub use_reset_password: bool,
    pub use_secrets_manager: bool,
    pub use_password_manager: bool,
    pub use_activate_autofill_policy: bool,
    pub use_automatic_user_confirmation: bool,
    pub self_host: bool,
    pub users_get_premium: bool,
    pub seats: u32,
    pub max_collections: u32,
    pub max_storage_gb: Option<u32>,
    pub sso_bound: bool,
    pub identifier: Option<String>,
    pub permissions: Permissions,
    pub reset_password_enrolled: bool,
    pub user_id: Option<Uuid>,
    pub organization_user_id: Option<Uuid>,
    pub has_public_and_private_keys: bool,
    pub provider_id: Option<Uuid>,
    pub provider_name: Option<String>,
    pub provider_type: Option<ProviderType>,
    pub is_provider_user: bool,
    pub is_member: bool,
    pub family_sponsorship_friendly_name: Option<String>,
    pub family_sponsorship_available: bool,
    pub product_tier_type: ProductTierType,
    pub key_connector_enabled: bool,
    pub key_connector_url: Option<String>,
    pub family_sponsorship_last_sync_date: Option<DateTime<Utc>>,
    pub family_sponsorship_valid_until: Option<DateTime<Utc>>,
    pub family_sponsorship_to_delete: Option<bool>,
    pub access_secrets_manager: bool,
    pub limit_collection_creation: bool,
    pub limit_collection_deletion: bool,
    pub limit_item_deletion: bool,
    pub allow_admin_access_to_all_collection_items: bool,
    pub user_is_managed_by_organization: bool,
    pub use_access_intelligence: bool,
    pub use_admin_sponsored_families: bool,
    pub use_disable_sm_ads_for_users: bool,
    pub is_admin_initiated: bool,
    pub sso_enabled: bool,
    pub sso_member_decryption_type: Option<MemberDecryptionType>,
    pub use_phishing_blocker: bool,
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
            seats: 0,
            max_collections: 0,
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
