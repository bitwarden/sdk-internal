/*
 * Bitwarden Internal API
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: latest
 *
 * Generated by: https://openapi-generator.tech
 */

use serde::{Deserialize, Serialize};

use crate::models;

///
#[repr(i64)]
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    serde_repr::Serialize_repr,
    serde_repr::Deserialize_repr,
)]
pub enum PushType {
    SyncCipherUpdate = 0,
    SyncCipherCreate = 1,
    SyncLoginDelete = 2,
    SyncFolderDelete = 3,
    SyncCiphers = 4,
    SyncVault = 5,
    SyncOrgKeys = 6,
    SyncFolderCreate = 7,
    SyncFolderUpdate = 8,
    SyncCipherDelete = 9,
    SyncSettings = 10,
    LogOut = 11,
    SyncSendCreate = 12,
    SyncSendUpdate = 13,
    SyncSendDelete = 14,
    AuthRequest = 15,
    AuthRequestResponse = 16,
    SyncOrganizations = 17,
    SyncOrganizationStatusChanged = 18,
    SyncOrganizationCollectionSettingChanged = 19,
    Notification = 20,
    NotificationStatus = 21,
    PendingSecurityTasks = 22,
}

impl std::fmt::Display for PushType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::SyncCipherUpdate => write!(f, "0"),
            Self::SyncCipherCreate => write!(f, "1"),
            Self::SyncLoginDelete => write!(f, "2"),
            Self::SyncFolderDelete => write!(f, "3"),
            Self::SyncCiphers => write!(f, "4"),
            Self::SyncVault => write!(f, "5"),
            Self::SyncOrgKeys => write!(f, "6"),
            Self::SyncFolderCreate => write!(f, "7"),
            Self::SyncFolderUpdate => write!(f, "8"),
            Self::SyncCipherDelete => write!(f, "9"),
            Self::SyncSettings => write!(f, "10"),
            Self::LogOut => write!(f, "11"),
            Self::SyncSendCreate => write!(f, "12"),
            Self::SyncSendUpdate => write!(f, "13"),
            Self::SyncSendDelete => write!(f, "14"),
            Self::AuthRequest => write!(f, "15"),
            Self::AuthRequestResponse => write!(f, "16"),
            Self::SyncOrganizations => write!(f, "17"),
            Self::SyncOrganizationStatusChanged => write!(f, "18"),
            Self::SyncOrganizationCollectionSettingChanged => write!(f, "19"),
            Self::Notification => write!(f, "20"),
            Self::NotificationStatus => write!(f, "21"),
            Self::PendingSecurityTasks => write!(f, "22"),
        }
    }
}

impl Default for PushType {
    fn default() -> PushType {
        Self::SyncCipherUpdate
    }
}
