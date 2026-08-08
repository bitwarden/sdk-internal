//! Concrete [`Policy`] implementations, one per [`PolicyType`].

use bitwarden_organizations::OrganizationUserType;

use crate::{MasterPasswordPolicyResponse, Policy, PolicyType, policy_type::PolicyDataType};

/// Two-factor Authentication policy.
pub struct TwoFactorAuthenticationPolicy;

impl Policy for TwoFactorAuthenticationPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::TwoFactorAuthentication
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::TwoFactorAuthentication
    }
}

/// Master Password policy.
pub struct MasterPasswordPolicy;

impl Policy for MasterPasswordPolicy {
    type Data = MasterPasswordPolicyResponse;

    fn policy_type(&self) -> PolicyType {
        PolicyType::MasterPassword
    }

    fn to_erased(&self, data: Self::Data) -> PolicyDataType {
        PolicyDataType::MasterPassword(data)
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

/// Password Generator policy.
pub struct PasswordGeneratorPolicy;

impl Policy for PasswordGeneratorPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::PasswordGenerator
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::PasswordGenerator
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

/// Single Organization policy.
pub struct SingleOrgPolicy;

impl Policy for SingleOrgPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::SingleOrg
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::SingleOrg
    }
}

/// Require Single Sign-On policy.
pub struct RequireSsoPolicy;

impl Policy for RequireSsoPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::RequireSso
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::RequireSso
    }
}

/// Organization Data Ownership policy.
pub struct OrganizationDataOwnershipPolicy;

impl Policy for OrganizationDataOwnershipPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::OrganizationDataOwnership
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::OrganizationDataOwnership
    }
}

/// Disable Send policy.
pub struct DisableSendPolicy;

impl Policy for DisableSendPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::DisableSend
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::DisableSend
    }
}

/// Send Options policy.
pub struct SendOptionsPolicy;

impl Policy for SendOptionsPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::SendOptions
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::SendOptions
    }
}

/// Account Recovery Administration policy.
pub struct ResetPasswordPolicy;

impl Policy for ResetPasswordPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::ResetPassword
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::ResetPassword
    }
}

/// Maximum Vault Timeout policy.
pub struct MaximumVaultTimeoutPolicy;

impl Policy for MaximumVaultTimeoutPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::MaximumVaultTimeout
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::MaximumVaultTimeout
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[OrganizationUserType::Owner]
    }
}

/// Disable Personal Vault Export policy.
pub struct DisablePersonalVaultExportPolicy;

impl Policy for DisablePersonalVaultExportPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::DisablePersonalVaultExport
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::DisablePersonalVaultExport
    }
}

/// Activate Autofill policy.
pub struct ActivateAutofillPolicy;

impl Policy for ActivateAutofillPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::ActivateAutofill
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::ActivateAutofill
    }
}

/// Automatic App Log-in policy.
pub struct AutomaticAppLogInPolicy;

impl Policy for AutomaticAppLogInPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::AutomaticAppLogIn
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::AutomaticAppLogIn
    }
}

/// Free Families Sponsorship policy.
pub struct FreeFamiliesSponsorshipPolicy;

impl Policy for FreeFamiliesSponsorshipPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::FreeFamiliesSponsorship
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::FreeFamiliesSponsorship
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

/// Remove Unlock with PIN policy.
pub struct RemoveUnlockWithPinPolicy;

impl Policy for RemoveUnlockWithPinPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::RemoveUnlockWithPin
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::RemoveUnlockWithPin
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

/// Restricted Item Types policy.
pub struct RestrictedItemTypesPolicy;

impl Policy for RestrictedItemTypesPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::RestrictedItemTypes
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::RestrictedItemTypes
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

/// URI Match Defaults policy.
pub struct UriMatchDefaultsPolicy;

impl Policy for UriMatchDefaultsPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::UriMatchDefaults
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::UriMatchDefaults
    }
}

/// Autotype Default Setting policy.
pub struct AutotypeDefaultSettingPolicy;

impl Policy for AutotypeDefaultSettingPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::AutotypeDefaultSetting
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::AutotypeDefaultSetting
    }
}

/// Automatic User Confirmation policy.
pub struct AutomaticUserConfirmationPolicy;

impl Policy for AutomaticUserConfirmationPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::AutomaticUserConfirmation
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::AutomaticUserConfirmation
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

/// Block Claimed Domain Account Creation policy.
pub struct BlockClaimedDomainAccountCreationPolicy;

impl Policy for BlockClaimedDomainAccountCreationPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::BlockClaimedDomainAccountCreation
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::BlockClaimedDomainAccountCreation
    }
}

/// Organization User Notification policy.
pub struct OrganizationUserNotificationPolicy;

impl Policy for OrganizationUserNotificationPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::OrganizationUserNotification
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::OrganizationUserNotification
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

/// Send Controls policy.
pub struct SendControlsPolicy;

impl Policy for SendControlsPolicy {
    type Data = ();

    fn policy_type(&self) -> PolicyType {
        PolicyType::SendControls
    }

    fn to_erased(&self, _data: Self::Data) -> PolicyDataType {
        PolicyDataType::SendControls
    }
}
