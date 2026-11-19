#![doc = include_str!("../README.md")]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
#[cfg(feature = "uniffi")]
mod uniffi_support;

mod organizations_client;
mod profile;
mod types;

pub use organizations_client::{OrganizationsClient, OrganizationsClientExt};
pub use profile::{
    CollectionManagementSettings, FamilySponsorship, OrganizationDetails, OrganizationMembership,
    OrganizationPlan, OrganizationProvider, ProfileOrganization, SsoSettings,
};
pub use types::{
    MemberDecryptionType, OrganizationUserId, OrganizationUserStatusType, OrganizationUserType,
    Permissions, ProductTierType, ProviderId, ProviderType,
};
