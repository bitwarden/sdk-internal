use bitwarden_api_api::models::{
    EmergencyAccessGranteeDetailsResponseModel, EmergencyAccessGrantorDetailsResponseModel,
    EmergencyAccessStatusType as ApiEmergencyAccessStatus,
    EmergencyAccessType as ApiEmergencyAccessType,
};
use bitwarden_core::{MissingFieldError, UserId, require};
use bitwarden_uuid::uuid_newtype;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

uuid_newtype!(pub EmergencyAccessId);

/// What the grantee may do once access is granted.
#[derive(Serialize_repr, Deserialize_repr, Debug, Clone, Copy, PartialEq, Eq)]
#[bitwarden_ffi::wasm_object]
#[repr(u8)]
pub enum EmergencyAccessType {
    /// The grantee may view the grantor's vault.
    View = 0,
    /// The grantee may reset the grantor's master password and take over the account.
    Takeover = 1,
}

/// Where an emergency access is in its lifecycle.
#[derive(Serialize_repr, Deserialize_repr, Debug, Clone, Copy, PartialEq, Eq)]
#[bitwarden_ffi::wasm_object]
#[repr(u8)]
pub enum EmergencyAccessStatus {
    /// The grantor invited the grantee.
    Invited = 0,
    /// The grantee accepted the invite.
    Accepted = 1,
    /// The grantor shared their user key with the grantee.
    Confirmed = 2,
    /// The grantee requested access and is waiting for approval or the wait time to pass.
    RecoveryInitiated = 3,
    /// Access was granted to the grantee.
    RecoveryApproved = 4,
}

/// An emergency access seen by the grantor, describing the trusted grantee.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
#[bitwarden_ffi::wasm_record]
pub struct GranteeEmergencyAccess {
    /// The emergency access ID.
    pub id: EmergencyAccessId,
    /// The grantee's user ID, absent until the grantee accepted the invite.
    pub grantee_id: Option<UserId>,
    /// The grantee's name.
    pub name: Option<String>,
    /// The grantee's email.
    pub email: Option<String>,
    /// What the grantee may do once access is granted.
    pub r#type: EmergencyAccessType,
    /// Where the emergency access is in its lifecycle.
    pub status: EmergencyAccessStatus,
    /// Days after a request until access is granted automatically.
    pub wait_time_days: i32,
    /// The grantee's avatar color.
    pub avatar_color: Option<String>,
}

/// An emergency access seen by the grantee, describing the grantor who trusts them.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
#[bitwarden_ffi::wasm_record]
pub struct GrantorEmergencyAccess {
    /// The emergency access ID.
    pub id: EmergencyAccessId,
    /// The grantor's user ID.
    pub grantor_id: UserId,
    /// The grantor's name.
    pub name: Option<String>,
    /// The grantor's email.
    pub email: Option<String>,
    /// What the current user may do once access is granted.
    pub r#type: EmergencyAccessType,
    /// Where the emergency access is in its lifecycle.
    pub status: EmergencyAccessStatus,
    /// Days after a request until access is granted automatically.
    pub wait_time_days: i32,
    /// The grantor's avatar color.
    pub avatar_color: Option<String>,
}

impl TryFrom<ApiEmergencyAccessType> for EmergencyAccessType {
    type Error = MissingFieldError;

    fn try_from(value: ApiEmergencyAccessType) -> Result<Self, Self::Error> {
        Ok(match value {
            ApiEmergencyAccessType::View => Self::View,
            ApiEmergencyAccessType::Takeover => Self::Takeover,
            ApiEmergencyAccessType::__Unknown(_) => return Err(MissingFieldError("type")),
        })
    }
}

impl From<EmergencyAccessType> for ApiEmergencyAccessType {
    fn from(value: EmergencyAccessType) -> Self {
        match value {
            EmergencyAccessType::View => Self::View,
            EmergencyAccessType::Takeover => Self::Takeover,
        }
    }
}

impl TryFrom<ApiEmergencyAccessStatus> for EmergencyAccessStatus {
    type Error = MissingFieldError;

    fn try_from(value: ApiEmergencyAccessStatus) -> Result<Self, Self::Error> {
        Ok(match value {
            ApiEmergencyAccessStatus::Invited => Self::Invited,
            ApiEmergencyAccessStatus::Accepted => Self::Accepted,
            ApiEmergencyAccessStatus::Confirmed => Self::Confirmed,
            ApiEmergencyAccessStatus::RecoveryInitiated => Self::RecoveryInitiated,
            ApiEmergencyAccessStatus::RecoveryApproved => Self::RecoveryApproved,
            ApiEmergencyAccessStatus::__Unknown(_) => return Err(MissingFieldError("status")),
        })
    }
}

impl TryFrom<EmergencyAccessGranteeDetailsResponseModel> for GranteeEmergencyAccess {
    type Error = MissingFieldError;

    fn try_from(response: EmergencyAccessGranteeDetailsResponseModel) -> Result<Self, Self::Error> {
        Ok(Self {
            id: EmergencyAccessId::new(require!(response.id)),
            grantee_id: response.grantee_id.map(UserId::new),
            name: response.name,
            email: response.email,
            r#type: require!(response.r#type).try_into()?,
            status: require!(response.status).try_into()?,
            wait_time_days: require!(response.wait_time_days),
            avatar_color: response.avatar_color,
        })
    }
}

impl TryFrom<EmergencyAccessGrantorDetailsResponseModel> for GrantorEmergencyAccess {
    type Error = MissingFieldError;

    fn try_from(response: EmergencyAccessGrantorDetailsResponseModel) -> Result<Self, Self::Error> {
        Ok(Self {
            id: EmergencyAccessId::new(require!(response.id)),
            grantor_id: UserId::new(require!(response.grantor_id)),
            name: response.name,
            email: response.email,
            r#type: require!(response.r#type).try_into()?,
            status: require!(response.status).try_into()?,
            wait_time_days: require!(response.wait_time_days),
            avatar_color: response.avatar_color,
        })
    }
}
