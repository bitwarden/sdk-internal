use bitwarden_api_api::models::CollectionDetailsResponseModel;
use bitwarden_core::{
    key_management::{KeyIds, SymmetricKeyId},
    require,
};
use bitwarden_crypto::{CryptoError, Decryptable, EncString, IdentifyKey, KeyStoreContext};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::VaultParseError;

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify_next::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct Collection {
    pub id: Option<Uuid>,
    pub organization_id: Uuid,

    pub name: EncString,

    pub external_id: Option<String>,
    pub hide_passwords: bool,
    pub read_only: bool,
    pub manage: bool,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CollectionView {
    pub id: Option<Uuid>,
    pub organization_id: Uuid,

    pub name: String,

    pub external_id: Option<String>,
    pub hide_passwords: bool,
    pub read_only: bool,
    pub manage: bool,
}

impl IdentifyKey<SymmetricKeyId> for Collection {
    fn key_identifier(&self) -> SymmetricKeyId {
        SymmetricKeyId::Organization(self.organization_id)
    }
}

impl Decryptable<KeyIds, SymmetricKeyId, CollectionView> for Collection {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<CollectionView, CryptoError> {
        Ok(CollectionView {
            id: self.id,
            organization_id: self.organization_id,

            name: self.name.decrypt(ctx, key).ok().unwrap_or_default(),

            external_id: self.external_id.clone(),
            hide_passwords: self.hide_passwords,
            read_only: self.read_only,
            manage: self.manage,
        })
    }
}

impl TryFrom<CollectionDetailsResponseModel> for Collection {
    type Error = VaultParseError;

    fn try_from(collection: CollectionDetailsResponseModel) -> Result<Self, Self::Error> {
        Ok(Collection {
            id: collection.id,
            organization_id: require!(collection.organization_id),
            name: require!(collection.name).parse()?,
            external_id: collection.external_id,
            hide_passwords: collection.hide_passwords.unwrap_or(false),
            read_only: collection.read_only.unwrap_or(false),
            manage: collection.manage.unwrap_or(false),
        })
    }
}
