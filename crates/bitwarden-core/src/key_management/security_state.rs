//! Security state is a signed object that attests to a user's (or later an organization's) security
//! state. The security goal is to prevent downgrades of specific features within the user's account
//! by the server / a networked attacker with TLS introspection access.
//!
//! A security state contains a security version. Based on this version, features can be disabled.
//! Since the server cannot sign a security state, it can no longer downgrade the feature, because
//! it cannot produce an arbitrary valid signed security state.
//!
//! Note: A long-term compromised server can record the security state of a user, and then replay
//! this specific state, or the entire account to downgrade users to previous states. This can be
//! prevented per logged in session by the client, and for bootstrapping a client by
//! using an extended login-with-device protocol.
//!
//! To utilize the security state to disable a feature the following steps are taken:
//! 1. Assume: Feature with format version A is insecure, and cannot be changed by simple mutation
//! 2. A new, safe format version B is introduced, and an upgrade path created
//! 3. The upgrade path is made mandatory
//! 4. After upgrades are run, the sdk validates that all items are in format version B, and the
//!    security state can be updated to contain the security version N+1
//! 5. The client, given a security state with security version N+1 will reject all items that are
//!    in format version A.

use std::str::FromStr;

use bitwarden_crypto::{
    CoseSerializable, CoseSign1Bytes, CryptoError, EncodingError, KeyIds, KeyStoreContext,
    SignedObject, SigningNamespace, VerifyingKey,
};
use bitwarden_encoding::{B64, FromStrVisitor};
use serde::{Deserialize, Serialize};

use crate::UserId;

#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
export type SignedSecurityState = string;
"#;

/// The security state is a signed object attesting to the security state of a user.
///
/// It contains a version, which can only ever increment. Based on the version, old formats and
/// features are blocked. This prevents a server from downgrading a user's account features, because
/// only the user can create this signed object.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityState {
    /// The entity ID is a permanent, unchangeable, unique identifier for the object this security
    /// state applies to. For users, this is the user ID, which never changes.
    entity_id: UserId,
    /// The version of the security state gates feature availability. It can only ever be
    /// incremented. Components can use it to gate format support of specific formats (like
    /// item url hashes).
    version: u64,
}

impl SecurityState {
    /// Initialize a new `SecurityState` for the given user ID, to the lowest version possible.
    /// The user needs to be a v2 encryption user.
    pub fn initialize_for_user(user_id: UserId) -> Self {
        SecurityState {
            entity_id: user_id,
            version: 2,
        }
    }

    /// Returns the version of the security state
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Signs the `SecurityState` with the provided signing key ID from the context.
    pub fn sign<Ids: KeyIds>(
        &self,
        signing_key_id: Ids::Signing,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<SignedSecurityState, CryptoError> {
        Ok(SignedSecurityState(ctx.sign(
            signing_key_id,
            &self,
            &SigningNamespace::SecurityState,
        )?))
    }
}

/// A signed and serialized `SecurityState` object.
#[derive(Clone, Debug)]
pub struct SignedSecurityState(pub(crate) SignedObject);

impl SignedSecurityState {
    /// Verifies the signature of the `SignedSecurityState` using the provided `VerifyingKey`.
    pub fn verify_and_unwrap(
        self,
        verifying_key: &VerifyingKey,
    ) -> Result<SecurityState, CryptoError> {
        self.0
            .verify_and_unwrap(verifying_key, &SigningNamespace::SecurityState)
    }
}

impl From<SignedSecurityState> for CoseSign1Bytes {
    fn from(val: SignedSecurityState) -> Self {
        val.0.to_cose()
    }
}

impl TryFrom<&CoseSign1Bytes> for SignedSecurityState {
    type Error = EncodingError;
    fn try_from(bytes: &CoseSign1Bytes) -> Result<Self, EncodingError> {
        Ok(SignedSecurityState(SignedObject::from_cose(bytes)?))
    }
}

impl From<SignedSecurityState> for String {
    fn from(val: SignedSecurityState) -> Self {
        let bytes: CoseSign1Bytes = val.into();
        B64::from(bytes.as_ref()).to_string()
    }
}

impl FromStr for SignedSecurityState {
    type Err = EncodingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = B64::try_from(s).map_err(|_| EncodingError::InvalidBase64Encoding)?;
        Self::try_from(&CoseSign1Bytes::from(&bytes))
    }
}

impl<'de> Deserialize<'de> for SignedSecurityState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new())
    }
}

impl serde::Serialize for SignedSecurityState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let b64_serialized_signed_public_key: String = self.clone().into();
        serializer.serialize_str(&b64_serialized_signed_public_key)
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_crypto::{KeyStore, SignatureAlgorithm, SigningKey};

    use super::*;
    use crate::key_management::{KeyIds, SigningKeyId};

    #[test]
    fn test_security_state_signing() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();

        let user_id = UserId::new_v4();
        let security_state = SecurityState::initialize_for_user(user_id);
        let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519);
        #[allow(deprecated)]
        ctx.set_signing_key(SigningKeyId::Local(""), signing_key.clone())
            .unwrap();
        let signed_security_state = security_state
            .sign(SigningKeyId::Local(""), &mut ctx)
            .unwrap();

        let verifying_key = signing_key.to_verifying_key();
        let verified_security_state = signed_security_state
            .verify_and_unwrap(&verifying_key)
            .unwrap();

        assert_eq!(verified_security_state.entity_id, user_id);
        assert_eq!(verified_security_state.version(), 2);
    }
}
