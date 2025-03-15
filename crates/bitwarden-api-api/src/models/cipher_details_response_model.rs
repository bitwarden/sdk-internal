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

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
pub struct CipherDetailsResponseModel {
    #[serde(rename = "object", skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    #[serde(rename = "id", skip_serializing_if = "Option::is_none")]
    pub id: Option<uuid::Uuid>,
    #[serde(rename = "organizationId", skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<uuid::Uuid>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub r#type: Option<models::CipherType>,
    #[serde(rename = "data", skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(rename = "name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "notes", skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(rename = "login", skip_serializing_if = "Option::is_none")]
    pub login: Option<Box<models::CipherLoginModel>>,
    #[serde(rename = "card", skip_serializing_if = "Option::is_none")]
    pub card: Option<Box<models::CipherCardModel>>,
    #[serde(rename = "identity", skip_serializing_if = "Option::is_none")]
    pub identity: Option<Box<models::CipherIdentityModel>>,
    #[serde(rename = "secureNote", skip_serializing_if = "Option::is_none")]
    pub secure_note: Option<Box<models::CipherSecureNoteModel>>,
    #[serde(rename = "sshKey", skip_serializing_if = "Option::is_none")]
    pub ssh_key: Option<Box<models::CipherSshKeyModel>>,
    #[serde(rename = "fields", skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<models::CipherFieldModel>>,
    #[serde(rename = "passwordHistory", skip_serializing_if = "Option::is_none")]
    pub password_history: Option<Vec<models::CipherPasswordHistoryModel>>,
    #[serde(rename = "attachments", skip_serializing_if = "Option::is_none")]
    pub attachments: Option<Vec<models::AttachmentResponseModel>>,
    #[serde(
        rename = "organizationUseTotp",
        skip_serializing_if = "Option::is_none"
    )]
    pub organization_use_totp: Option<bool>,
    #[serde(rename = "revisionDate", skip_serializing_if = "Option::is_none")]
    pub revision_date: Option<String>,
    #[serde(rename = "creationDate", skip_serializing_if = "Option::is_none")]
    pub creation_date: Option<String>,
    #[serde(rename = "deletedDate", skip_serializing_if = "Option::is_none")]
    pub deleted_date: Option<String>,
    #[serde(rename = "reprompt", skip_serializing_if = "Option::is_none")]
    pub reprompt: Option<models::CipherRepromptType>,
    #[serde(rename = "key", skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(rename = "folderId", skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<uuid::Uuid>,
    #[serde(rename = "favorite", skip_serializing_if = "Option::is_none")]
    pub favorite: Option<bool>,
    #[serde(rename = "edit", skip_serializing_if = "Option::is_none")]
    pub edit: Option<bool>,
    #[serde(rename = "viewPassword", skip_serializing_if = "Option::is_none")]
    pub view_password: Option<bool>,
    #[serde(rename = "permissions", skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Box<models::CipherPermissionsResponseModel>>,
    #[serde(rename = "collectionIds", skip_serializing_if = "Option::is_none")]
    pub collection_ids: Option<Vec<uuid::Uuid>>,
}

impl CipherDetailsResponseModel {
    pub fn new() -> CipherDetailsResponseModel {
        CipherDetailsResponseModel {
            object: None,
            id: None,
            organization_id: None,
            r#type: None,
            data: None,
            name: None,
            notes: None,
            login: None,
            card: None,
            identity: None,
            secure_note: None,
            ssh_key: None,
            fields: None,
            password_history: None,
            attachments: None,
            organization_use_totp: None,
            revision_date: None,
            creation_date: None,
            deleted_date: None,
            reprompt: None,
            key: None,
            folder_id: None,
            favorite: None,
            edit: None,
            view_password: None,
            permissions: None,
            collection_ids: None,
        }
    }
}
