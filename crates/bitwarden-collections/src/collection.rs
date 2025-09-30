use bitwarden_api_api::models::CollectionDetailsResponseModel;
use bitwarden_core::{
    OrganizationId,
    key_management::{KeyIds, SymmetricKeyId},
    require,
};
use bitwarden_crypto::{CryptoError, Decryptable, EncString, IdentifyKey, KeyStoreContext};
use bitwarden_uuid::uuid_newtype;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use uuid::Uuid;
#[cfg(feature = "wasm")]
use {tsify::Tsify, wasm_bindgen::prelude::*};

use crate::{error::CollectionsParseError, tree::TreeItem};

uuid_newtype!(pub CollectionId);

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct Collection {
    pub id: Option<CollectionId>,
    pub organization_id: OrganizationId,
    pub name: EncString,
    pub external_id: Option<String>,
    pub hide_passwords: bool,
    pub read_only: bool,
    pub manage: bool,
    pub default_user_collection_email: Option<String>,
    pub r#type: CollectionType,
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct CollectionView {
    pub id: Option<CollectionId>,
    pub organization_id: OrganizationId,
    pub name: String,
    pub external_id: Option<String>,
    pub hide_passwords: bool,
    pub read_only: bool,
    pub manage: bool,
    pub r#type: CollectionType,
}

/// Type of collection
#[derive(Serialize_repr, Deserialize_repr, Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
#[repr(u8)]
pub enum CollectionType {
    /// Default collection type. Can be assigned by an organization to user(s) or group(s)
    SharedCollection = 0,
    /// Default collection assigned to a user for an organization that has
    /// OrganizationDataOwnership (formerly PersonalOwnership) policy enabled.
    DefaultUserCollection = 1,
}

#[allow(missing_docs)]
impl Decryptable<KeyIds, SymmetricKeyId, CollectionView> for Collection {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<CollectionView, CryptoError> {
        let name = self
            .default_user_collection_email
            .as_ref()
            .unwrap_or(&self.name.decrypt(ctx, key)?)
            .clone();

        Ok(CollectionView {
            id: self.id,
            organization_id: self.organization_id,
            name,
            external_id: self.external_id.clone(),
            hide_passwords: self.hide_passwords,
            read_only: self.read_only,
            manage: self.manage,
            r#type: self.r#type.clone(),
        })
    }
}

#[allow(missing_docs)]
impl TryFrom<CollectionDetailsResponseModel> for Collection {
    type Error = CollectionsParseError;

    fn try_from(collection: CollectionDetailsResponseModel) -> Result<Self, Self::Error> {
        Ok(Collection {
            id: collection.id.map(CollectionId::new),
            organization_id: OrganizationId::new(require!(collection.organization_id)),
            name: require!(collection.name).parse()?,
            external_id: collection.external_id,
            hide_passwords: collection.hide_passwords.unwrap_or(false),
            read_only: collection.read_only.unwrap_or(false),
            manage: collection.manage.unwrap_or(false),
            default_user_collection_email: collection.default_user_collection_email,
            r#type: require!(collection.r#type).into(),
        })
    }
}

#[allow(missing_docs)]
impl IdentifyKey<SymmetricKeyId> for Collection {
    fn key_identifier(&self) -> SymmetricKeyId {
        SymmetricKeyId::Organization(self.organization_id)
    }
}

#[allow(missing_docs)]
impl TreeItem for CollectionView {
    fn id(&self) -> Uuid {
        self.id.map(|id| id.0).unwrap_or_default()
    }

    fn short_name(&self) -> &str {
        self.path().last().unwrap_or(&"")
    }

    fn path(&self) -> Vec<&str> {
        self.name
            .split(Self::DELIMITER)
            .filter(|s| !s.is_empty())
            .collect::<Vec<&str>>()
    }

    const DELIMITER: char = '/';
}

impl From<bitwarden_api_api::models::CollectionType> for CollectionType {
    fn from(collection_type: bitwarden_api_api::models::CollectionType) -> Self {
        match collection_type {
            bitwarden_api_api::models::CollectionType::SharedCollection => Self::SharedCollection,
            bitwarden_api_api::models::CollectionType::DefaultUserCollection => {
                Self::DefaultUserCollection
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::key_management::{KeyIds, SymmetricKeyId};
    use bitwarden_crypto::{KeyStore, PrimitiveEncryptable, SymmetricCryptoKey};

    use super::*;

    const ORGANIZATION_ID: &str = "12345678-1234-1234-1234-123456789012";
    const COLLECTION_ID: &str = "87654321-4321-4321-4321-210987654321";

    // Helper function to create a test key store with a symmetric key
    fn create_test_key_store() -> KeyStore<KeyIds> {
        let store = KeyStore::<KeyIds>::default();
        let key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
        let org_id = ORGANIZATION_ID.parse().unwrap();

        #[allow(deprecated)]
        store
            .context_mut()
            .set_symmetric_key(SymmetricKeyId::Organization(org_id), key)
            .unwrap();

        store
    }

    #[test]
    fn test_decrypt_with_name_only() {
        let store = create_test_key_store();
        let mut ctx = store.context();
        let org_id = ORGANIZATION_ID.parse().unwrap();
        let key = SymmetricKeyId::Organization(org_id);

        let collection_name: &str = "Collection Name";

        let collection = Collection {
            id: Some(COLLECTION_ID.parse().unwrap()),
            organization_id: org_id,
            name: collection_name.encrypt(&mut ctx, key).unwrap(),
            external_id: Some("external-id".to_string()),
            hide_passwords: true,
            read_only: false,
            manage: true,
            default_user_collection_email: None,
            r#type: CollectionType::SharedCollection,
        };

        let decrypted = collection.decrypt(&mut ctx, key).unwrap();

        assert_eq!(decrypted.name, collection_name);
    }

    #[test]
    fn test_decrypt_with_default_user_collection_email() {
        let store = create_test_key_store();
        let mut ctx = store.context();
        let org_id = ORGANIZATION_ID.parse().unwrap();
        let key = SymmetricKeyId::Organization(org_id);

        let collection_name: &str = "Collection Name";
        let default_user_collection_email = String::from("test-user@bitwarden.com");

        let collection = Collection {
            id: Some(COLLECTION_ID.parse().unwrap()),
            organization_id: org_id,
            name: collection_name.encrypt(&mut ctx, key).unwrap(),
            external_id: None,
            hide_passwords: false,
            read_only: true,
            manage: false,
            default_user_collection_email: Some(default_user_collection_email.clone()),
            r#type: CollectionType::SharedCollection,
        };

        let decrypted = collection.decrypt(&mut ctx, key).unwrap();

        assert_ne!(decrypted.name, collection_name);
        assert_eq!(decrypted.name, default_user_collection_email);
    }

    #[test]
    fn test_decrypt_all_fields_preserved() {
        let store = create_test_key_store();
        let mut ctx = store.context();
        let org_id = ORGANIZATION_ID.parse().unwrap();
        let key = SymmetricKeyId::Organization(org_id);

        let collection_id = Some(COLLECTION_ID.parse().unwrap());
        let external_id = Some("external-test-id".to_string());
        let collection_name: &str = "Collection Name";
        let collection_type = CollectionType::SharedCollection;

        let collection = Collection {
            id: collection_id,
            organization_id: org_id,
            name: collection_name.encrypt(&mut ctx, key).unwrap(),
            external_id: external_id.clone(),
            hide_passwords: true,
            read_only: true,
            manage: true,
            default_user_collection_email: None,
            r#type: collection_type.clone(),
        };

        let decrypted = collection.decrypt(&mut ctx, key).unwrap();

        // Verify all fields are correctly transferred
        assert_eq!(decrypted.id, collection.id);
        assert_eq!(decrypted.organization_id, collection.organization_id);
        assert_eq!(decrypted.name, collection_name);
        assert_eq!(decrypted.external_id, external_id);
        assert_eq!(decrypted.hide_passwords, collection.hide_passwords);
        assert_eq!(decrypted.read_only, collection.read_only);
        assert_eq!(decrypted.manage, collection.manage);
        assert_eq!(decrypted.r#type, collection_type);
    }
}
