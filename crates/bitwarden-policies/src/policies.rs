//! Concrete [`Policy`] implementations, one per [`PolicyType`].
//! Future note: once the policies crate is stable, this file will be
//! broken up and each Policy implementation distributed to the team
//! that owns its domain.

use bitwarden_organizations::OrganizationUserType;

use crate::{Policy, PolicyType};

/// Two-factor Authentication policy.
pub struct TwoFactorAuthenticationPolicy;

impl Policy for TwoFactorAuthenticationPolicy {
    fn policy_type(&self) -> PolicyType {
        PolicyType::TwoFactorAuthentication
    }
}

/// Master Password policy.
pub struct MasterPasswordPolicy;

impl Policy for MasterPasswordPolicy {
    fn policy_type(&self) -> PolicyType {
        PolicyType::MasterPassword
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

/// Password Generator policy.
pub struct PasswordGeneratorPolicy;

impl Policy for PasswordGeneratorPolicy {
    fn policy_type(&self) -> PolicyType {
        PolicyType::PasswordGenerator
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

/// Single Organization policy.
pub struct SingleOrgPolicy;

impl Policy for SingleOrgPolicy {
    fn policy_type(&self) -> PolicyType {
        PolicyType::SingleOrg
    }
}

/// Require Single Sign-On policy.
pub struct RequireSsoPolicy;

impl Policy for RequireSsoPolicy {
    fn policy_type(&self) -> PolicyType {
        PolicyType::RequireSso
    }
}

/// Organization Data Ownership policy.
pub struct OrganizationDataOwnershipPolicy;

impl Policy for OrganizationDataOwnershipPolicy {
    fn policy_type(&self) -> PolicyType {
        PolicyType::OrganizationDataOwnership
    }
}

/// Disable Send policy.
pub struct DisableSendPolicy;

impl Policy for DisableSendPolicy {
    fn policy_type(&self) -> PolicyType {
        PolicyType::DisableSend
    }
}

/// Send Options policy.
pub struct SendOptionsPolicy;

impl Policy for SendOptionsPolicy {
    fn policy_type(&self) -> PolicyType {
        PolicyType::SendOptions
    }
}

/// Account Recovery Administration policy.
pub struct ResetPasswordPolicy;

impl Policy for ResetPasswordPolicy {
    fn policy_type(&self) -> PolicyType {
        PolicyType::ResetPassword
    }
}

/// Maximum Vault Timeout policy.
pub struct MaximumVaultTimeoutPolicy;

impl Policy for MaximumVaultTimeoutPolicy {
    fn policy_type(&self) -> PolicyType {
        PolicyType::MaximumVaultTimeout
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[OrganizationUserType::Owner]
    }
}

/// Disable Personal Vault Export policy.
pub struct DisablePersonalVaultExportPolicy;

impl Policy for DisablePersonalVaultExportPolicy {
    fn policy_type(&self) -> PolicyType {
        PolicyType::DisablePersonalVaultExport
    }
}

/// Activate Autofill policy.
pub struct ActivateAutofillPolicy;

impl Policy for ActivateAutofillPolicy {
    fn policy_type(&self) -> PolicyType {
        PolicyType::ActivateAutofill
    }
}

/// Automatic App Log-in policy.
pub struct AutomaticAppLogInPolicy;

impl Policy for AutomaticAppLogInPolicy {
    fn policy_type(&self) -> PolicyType {
        PolicyType::AutomaticAppLogIn
    }
}

/// Free Families Sponsorship policy.
pub struct FreeFamiliesSponsorshipPolicy;

impl Policy for FreeFamiliesSponsorshipPolicy {
    fn policy_type(&self) -> PolicyType {
        PolicyType::FreeFamiliesSponsorship
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

/// Remove Unlock with PIN policy.
pub struct RemoveUnlockWithPinPolicy;

impl Policy for RemoveUnlockWithPinPolicy {
    fn policy_type(&self) -> PolicyType {
        PolicyType::RemoveUnlockWithPin
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

/// Restricted Item Types policy.
pub struct RestrictedItemTypesPolicy;

impl Policy for RestrictedItemTypesPolicy {
    fn policy_type(&self) -> PolicyType {
        PolicyType::RestrictedItemTypes
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

/// URI Match Defaults policy.
pub struct UriMatchDefaultsPolicy;

impl Policy for UriMatchDefaultsPolicy {
    fn policy_type(&self) -> PolicyType {
        PolicyType::UriMatchDefaults
    }
}

/// Autotype Default Setting policy.
pub struct AutotypeDefaultSettingPolicy;

impl Policy for AutotypeDefaultSettingPolicy {
    fn policy_type(&self) -> PolicyType {
        PolicyType::AutotypeDefaultSetting
    }
}

/// Automatic User Confirmation policy.
pub struct AutomaticUserConfirmationPolicy;

impl Policy for AutomaticUserConfirmationPolicy {
    fn policy_type(&self) -> PolicyType {
        PolicyType::AutomaticUserConfirmation
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

/// Block Claimed Domain Account Creation policy.
pub struct BlockClaimedDomainAccountCreationPolicy;

impl Policy for BlockClaimedDomainAccountCreationPolicy {
    fn policy_type(&self) -> PolicyType {
        PolicyType::BlockClaimedDomainAccountCreation
    }
}

/// Organization User Notification policy.
pub struct OrganizationUserNotificationPolicy;

impl Policy for OrganizationUserNotificationPolicy {
    fn policy_type(&self) -> PolicyType {
        PolicyType::OrganizationUserNotification
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

/// Send Controls policy.
pub struct SendControlsPolicy;

impl Policy for SendControlsPolicy {
    fn policy_type(&self) -> PolicyType {
        PolicyType::SendControls
    }
}

/// Fill Assist policy.
pub struct FillAssistPolicy;

impl Policy for FillAssistPolicy {
    fn policy_type(&self) -> PolicyType {
        PolicyType::FillAssist
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}
