#![doc = include_str!("../README.md")]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
#[cfg(feature = "uniffi")]
mod uniffi_support;

use bitwarden_core::OrganizationId;
use bitwarden_uuid::uuid_newtype;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use uuid::Uuid;

uuid_newtype!(pub OrganizationUserId);

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
    /// User with a customized set of permissions as indicated by
    /// [`OrganizationMembership::permissions`].
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

/// Organization membership details from the user's profile sync.
///
/// Contains the full set of entitlements, plan features, and metadata for a single
/// organization that the current user belongs to.
#[derive(Default, PartialEq, Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
#[serde(rename_all = "camelCase")]
pub struct ProfileOrganization {
    /// Identity of the organization.
    pub details: OrganizationDetails,
    /// The organization's plan or license: tier, limits, and feature entitlements.
    pub plan: OrganizationPlan,
    /// The current user's relationship to the organization.
    pub membership: OrganizationMembership,
    /// Admin-configured collection management settings.
    pub collection_management: CollectionManagementSettings,
    /// The provider managing this organization, if any.
    pub provider: Option<OrganizationProvider>,
    /// The organization's SSO and Key Connector settings.
    pub sso: SsoSettings,
    /// Families sponsorship state for the current user.
    pub family_sponsorship: FamilySponsorship,
}

bitwarden_state::register_repository_item!(OrganizationId => ProfileOrganization, "ProfileOrganization");

/// Identity of the organization.
#[derive(PartialEq, Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
#[serde(rename_all = "camelCase")]
pub struct OrganizationDetails {
    /// Unique identifier for the organization.
    pub id: OrganizationId,
    /// Display name of the organization.
    pub name: String,
    /// Whether the organization is currently enabled.
    pub enabled: bool,
    /// Whether the organization has both a public and private key configured.
    pub has_public_and_private_keys: bool,
}

impl Default for OrganizationDetails {
    fn default() -> Self {
        OrganizationDetails {
            id: OrganizationId::new(Uuid::nil()),
            name: String::new(),
            enabled: true,
            has_public_and_private_keys: false,
        }
    }
}

/// The organization's plan or license: its tier, limits, and feature entitlements.
///
/// The `use_*` flags are entitlements set from the plan or license, not settings that
/// organization admins can toggle.
#[derive(PartialEq, Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
#[serde(rename_all = "camelCase")]
pub struct OrganizationPlan {
    /// The subscription tier of the organization.
    pub product_tier_type: ProductTierType,
    /// The number of licensed seats for the organization.
    pub seats: Option<u32>,
    /// The maximum number of collections the organization can create.
    pub max_collections: Option<u32>,
    /// The maximum encrypted storage in gigabytes, if limited.
    pub max_storage_gb: Option<u32>,
    /// Whether the organization can create a license file for a self-hosted instance.
    pub self_host: bool,
    /// Whether organization members receive premium features.
    pub users_get_premium: bool,
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
    /// Whether the organization can use Key Connector for decryption.
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
    /// Whether the organization has access to Privileged Access Management features.
    pub use_pam: bool,
    /// Whether the organization can use the activate autofill policy.
    pub use_activate_autofill_policy: bool,
    /// Whether the organization can automatically confirm new members without manual admin
    /// approval.
    pub use_automatic_user_confirmation: bool,
    /// Whether the organization has access to Access Intelligence features.
    pub use_access_intelligence: bool,
    /// Whether the organization can sponsor families plans for members (Families For Enterprises).
    pub use_admin_sponsored_families: bool,
    /// Whether Secrets Manager ads are disabled for users.
    #[serde(rename = "useDisableSMAdsForUsers")]
    pub use_disable_sm_ads_for_users: bool,
    /// Whether the organization has access to phishing blocker features.
    pub use_phishing_blocker: bool,
    /// Whether the organization has access to the My Items collection feature.
    /// This allows users to store personal items in the organization vault
    /// if the Centralize Organization Ownership policy is enabled.
    pub use_my_items: bool,
    /// Whether the organization can invite members using invite links.
    pub use_invite_links: bool,
}

impl Default for OrganizationPlan {
    fn default() -> Self {
        OrganizationPlan {
            product_tier_type: ProductTierType::Free,
            seats: Some(10),
            max_collections: None,
            max_storage_gb: None,
            self_host: false,
            users_get_premium: false,
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
            use_pam: false,
            use_activate_autofill_policy: false,
            use_automatic_user_confirmation: false,
            use_access_intelligence: false,
            use_admin_sponsored_families: false,
            use_disable_sm_ads_for_users: false,
            use_phishing_blocker: false,
            use_my_items: false,
            use_invite_links: false,
        }
    }
}

/// The current user's relationship to the organization.
#[derive(PartialEq, Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
#[serde(rename_all = "camelCase")]
pub struct OrganizationMembership {
    /// The user's membership status in the organization.
    pub status: OrganizationUserStatusType,
    /// The user's role in the organization.
    pub r#type: OrganizationUserType,
    /// The current user's custom permissions, relevant when [`OrganizationUserType::Custom`] is
    /// the user's `type`.
    pub permissions: Permissions,
    /// The current user's personal user ID.
    pub user_id: Option<Uuid>,
    /// The current user's organization membership ID.
    pub organization_user_id: Option<Uuid>,
    /// Whether the current user is a direct member of this organization (as opposed to
    /// provider-only access).
    pub is_member: bool,
    /// Whether the current user accesses this organization through a provider.
    pub is_provider_user: bool,
    /// Whether the current user is enrolled in account recovery for this organization.
    pub reset_password_enrolled: bool,
    /// Whether the current user's account is bound to this organization via SSO.
    pub sso_bound: bool,
    /// Whether the current user's account is claimed by this organization.
    pub user_is_claimed_by_organization: bool,
    /// Whether the current user has access to Secrets Manager for this organization.
    pub access_secrets_manager: bool,
}

impl Default for OrganizationMembership {
    fn default() -> Self {
        OrganizationMembership {
            status: OrganizationUserStatusType::Confirmed,
            r#type: OrganizationUserType::User,
            permissions: Permissions::default(),
            user_id: None,
            organization_user_id: None,
            is_member: true,
            is_provider_user: false,
            reset_password_enrolled: false,
            sso_bound: false,
            user_is_claimed_by_organization: false,
            access_secrets_manager: false,
        }
    }
}

/// Admin-configured settings controlling who can create, delete, and manage collections and
/// items.
#[derive(Default, PartialEq, Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
#[serde(rename_all = "camelCase")]
pub struct CollectionManagementSettings {
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
}

/// The provider managing an organization.
#[derive(PartialEq, Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
#[serde(rename_all = "camelCase")]
pub struct OrganizationProvider {
    /// The ID of the provider.
    pub id: Uuid,
    /// The type of provider.
    pub r#type: ProviderType,
    /// The name of the provider. `None` while the provider is pending setup.
    pub name: Option<String>,
}

/// An organization's SSO and Key Connector settings.
///
/// This mirrors the server's fields rather than modelling them as an enum, because the server
/// does not enforce the relationships between them: for example, a decryption type and Key
/// Connector URL can be present while SSO is disabled.
#[derive(Default, PartialEq, Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
#[serde(rename_all = "camelCase")]
pub struct SsoSettings {
    /// Whether SSO login is currently enabled for this organization.
    pub enabled: bool,
    /// The organization's SSO identifier.
    pub identifier: Option<String>,
    /// The decryption type used for SSO members. `None` when no SSO configuration has been
    /// saved.
    pub member_decryption_type: Option<MemberDecryptionType>,
    /// Whether members decrypt via Key Connector, as computed by the server.
    pub key_connector_enabled: bool,
    /// The URL of the Key Connector service. Only meaningful when
    /// [`key_connector_enabled`](Self::key_connector_enabled) is `true`.
    pub key_connector_url: Option<String>,
}

/// Families sponsorship state for the current user in an organization.
#[derive(Default, PartialEq, Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
#[serde(rename_all = "camelCase")]
pub struct FamilySponsorship {
    /// Whether the organization can sponsor a families plan for the current user. This can be
    /// `true` while a sponsorship exists.
    pub available: bool,
    /// The friendly name of the sponsorship, usually the recipient's email address. Set whenever
    /// a sponsorship exists.
    pub friendly_name: Option<String>,
    /// The date the sponsorship expires. `None` while the sponsorship has been offered but not
    /// yet redeemed.
    pub valid_until: Option<DateTime<Utc>>,
    /// The date the sponsorship was last synced between a self-hosted instance and the cloud.
    pub last_sync_date: Option<DateTime<Utc>>,
    /// Whether the sponsorship is scheduled for deletion.
    pub to_delete: Option<bool>,
    /// Whether the sponsorship was initiated by an organization admin.
    pub is_admin_initiated: bool,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// A record in the nested `ProfileOrganization` shape.
    fn organization_json() -> serde_json::Value {
        serde_json::from_str(
            r#"{
            "details": {
                "id": "0b5a2d2c-6b39-4c7e-9f4a-0a1b2c3d4e5f",
                "name": "Test Org",
                "enabled": true,
                "hasPublicAndPrivateKeys": true
            },
            "plan": {
                "productTierType": 3,
                "seats": 25,
                "maxCollections": null,
                "maxStorageGb": 5,
                "selfHost": false,
                "usersGetPremium": true,
                "usePolicies": true,
                "useGroups": true,
                "useDirectory": false,
                "useEvents": true,
                "useTotp": true,
                "use2fa": true,
                "useApi": false,
                "useSso": true,
                "useOrganizationDomains": false,
                "useKeyConnector": false,
                "useScim": false,
                "useCustomPermissions": true,
                "useResetPassword": true,
                "useSecretsManager": false,
                "usePasswordManager": true,
                "usePam": false,
                "useActivateAutofillPolicy": false,
                "useAutomaticUserConfirmation": false,
                "useAccessIntelligence": false,
                "useAdminSponsoredFamilies": false,
                "useDisableSMAdsForUsers": false,
                "usePhishingBlocker": false,
                "useMyItems": false,
                "useInviteLinks": true
            },
            "membership": {
                "status": 2,
                "type": 4,
                "permissions": {
                    "accessEventLogs": true,
                    "accessImportExport": false,
                    "accessReports": true,
                    "createNewCollections": false,
                    "editAnyCollection": false,
                    "deleteAnyCollection": false,
                    "manageGroups": true,
                    "manageSso": false,
                    "managePolicies": false,
                    "manageUsers": true,
                    "manageResetPassword": false,
                    "manageScim": false
                },
                "userId": "1c6b3e3d-7c4a-4d8f-8a5b-1b2c3d4e5f60",
                "organizationUserId": "2d7c4f4e-8d5b-4e9a-9b6c-2c3d4e5f6071",
                "isMember": true,
                "isProviderUser": false,
                "resetPasswordEnrolled": true,
                "ssoBound": false,
                "userIsClaimedByOrganization": false,
                "accessSecretsManager": false
            },
            "collectionManagement": {
                "limitCollectionCreation": true,
                "limitCollectionDeletion": true,
                "limitItemDeletion": false,
                "allowAdminAccessToAllCollectionItems": true
            },
            "provider": null,
            "sso": {
                "enabled": true,
                "identifier": "test-org",
                "memberDecryptionType": 0,
                "keyConnectorEnabled": false,
                "keyConnectorUrl": null
            },
            "familySponsorship": {
                "available": false,
                "friendlyName": null,
                "validUntil": null,
                "lastSyncDate": "2024-01-02T03:04:05Z",
                "toDelete": null,
                "isAdminInitiated": false
            }
        }"#,
        )
        .unwrap()
    }

    #[test]
    fn round_trips_organization_json() {
        let json = organization_json();

        let organization: ProfileOrganization = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(
            organization.details.id,
            OrganizationId::new("0b5a2d2c-6b39-4c7e-9f4a-0a1b2c3d4e5f".parse().unwrap())
        );
        assert!(organization.plan.use_invite_links);
        assert_eq!(organization.membership.r#type, OrganizationUserType::Custom);

        assert_eq!(serde_json::to_value(&organization).unwrap(), json);
    }

    #[test]
    fn deserializes_js_iso_date_strings() {
        let mut json = organization_json();
        json["familySponsorship"]["lastSyncDate"] = json!("2024-01-02T03:04:05.000Z");

        let organization: ProfileOrganization = serde_json::from_value(json).unwrap();
        assert_eq!(
            organization.family_sponsorship.last_sync_date,
            Some("2024-01-02T03:04:05Z".parse().unwrap())
        );
    }

    #[test]
    fn round_trips_provider_without_name() {
        let mut json = organization_json();
        json["provider"] = json!({
            "id": "3e8d5a5f-9e6c-4fab-8c7d-3d4e5f607182",
            "type": 2,
            "name": null
        });

        let organization: ProfileOrganization = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(
            organization.provider,
            Some(OrganizationProvider {
                id: "3e8d5a5f-9e6c-4fab-8c7d-3d4e5f607182".parse().unwrap(),
                r#type: ProviderType::BusinessUnit,
                name: None,
            })
        );

        assert_eq!(serde_json::to_value(&organization).unwrap(), json);
    }
}
