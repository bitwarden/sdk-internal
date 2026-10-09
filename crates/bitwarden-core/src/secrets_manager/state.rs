//! Secrets Manager state management.
//!
//! Secrets Manager supports persisting state to an encrypted file. This state file primarily
//! contains the auth token which circumvents rate limiting on frequent logins.
//!
//! The plaintext shape, versioning, and file I/O live here; the crypto (encrypting/decrypting
//! under the access token's derived key) lives in `bitwarden-access-token`, which never sees this
//! format.

use std::path::Path;

use bitwarden_access_token::{AccessTokenError, ExportedKey};
use bitwarden_crypto::EncString;
use serde::{Deserialize, Serialize};

use crate::auth::AccessToken;

/// Current version of the state file. This should be incremented whenever backwards incompatible
/// changes are done.
const STATE_VERSION: u32 = 1;

/// The content of the state file. Field names are part of the format and must not change.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ClientState {
    pub(crate) version: u32,
    pub(crate) token: String,
    pub(crate) encryption_key: ExportedKey,
}

#[allow(missing_docs)]
#[derive(Debug, thiserror::Error)]
pub enum StateFileError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    #[error(transparent)]
    Crypto(#[from] AccessTokenError),

    #[error("The state file version is invalid")]
    InvalidStateFileVersion,
}

impl ClientState {
    pub fn new(token: String, encryption_key: ExportedKey) -> Self {
        Self {
            version: STATE_VERSION,
            token,
            encryption_key,
        }
    }
}

/// Reads, parses and decrypts a state file using the provided access token.
pub(crate) fn get(
    state_file: &Path,
    access_token: &AccessToken,
) -> Result<ClientState, StateFileError> {
    let file_content = std::fs::read_to_string(state_file)?;

    // `EncString::from_str` never fails outright; unrecognized content becomes
    // `EncString::Unparseable`, which `decrypt` below rejects.
    let encrypted_state: EncString = file_content.parse().expect("EncString parsing never fails");
    let decrypted_state = access_token.decrypt(&encrypted_state)?;
    let client_state: ClientState = serde_json::from_slice(&decrypted_state)?;

    if client_state.version != STATE_VERSION {
        return Err(StateFileError::InvalidStateFileVersion);
    }

    Ok(client_state)
}

/// Serializes and encrypts the state using the provided access token.
pub(crate) fn set(
    state_file: &Path,
    access_token: &AccessToken,
    state: &ClientState,
) -> Result<(), StateFileError> {
    let serialized_state = serde_json::to_vec(state)?;
    let encrypted_state = access_token.encrypt(&serialized_state)?;

    Ok(std::fs::write(state_file, encrypted_state.to_string())?)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use bitwarden_access_token::AccessTokenKind;
    use bitwarden_crypto::{KeyStore, SymmetricCryptoKey, SymmetricKeyAlgorithm, key_slot_ids};

    use super::*;

    const ACCESS_TOKEN: &str = "0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";

    // Only used to install/inspect the exported key in these tests; production code never names
    // `SymmetricCryptoKey` or reaches into a key store directly.
    key_slot_ids! {
        #[symmetric]
        enum TestSymmSlotId {
            Organization,
            #[local]
            Local(LocalId),
        }

        #[private]
        enum TestPrivateSlotId {
            #[local]
            Local(LocalId),
        }

        #[signing]
        enum TestSigningSlotId {
            #[local]
            Local(LocalId),
        }

        TestKeySlotIds => TestSymmSlotId, TestPrivateSlotId, TestSigningSlotId;
    }

    fn access_token() -> AccessToken {
        AccessToken::parse(ACCESS_TOKEN, AccessTokenKind::SecretsManager).unwrap()
    }

    fn state_file_path() -> PathBuf {
        std::env::temp_dir().join(format!("sm-state-{}", uuid::Uuid::new_v4()))
    }

    /// Pinned state-file ciphertext, generated from HEAD (before this format moved out of
    /// `bitwarden-access-token`) by encrypting
    /// `{"version":1,"token":"a-jwt","encryption_key":<64 7-bytes>}` under [`ACCESS_TOKEN`]'s
    /// derived key. Must keep decrypting: existing state files on disk depend on it.
    const PINNED_STATE_FILE: &str = "2.2M+yObkE40jhxvdwdNaV6Q==|ZSvUF/8NKaOrlj75qqV+5oZA0ZbN+fnAdwtK1myuqOcQdz9GrrHs4fKco9HcGpMr9K0ZXVNOy371JV8/Zb9xA0G1EBEzNBAguw8LsvsDettAw2aMviUfkVfzryGfKeKy8dhq3xK+C4RqyXcppLnWxcnvvQsEpd0NbRDvex2J3/ZwcRX2bAb2oUX5oI99Vm1J|wMlFzdkaRMvnqyyfTQf3YU+C9ky5AJAECInAJsiSXs8=";

    #[test]
    fn pinned_state_file_decrypts() {
        let path = state_file_path();
        std::fs::write(&path, PINNED_STATE_FILE).unwrap();

        let state = get(&path, &access_token()).unwrap();
        std::fs::remove_file(&path).unwrap();

        assert_eq!(state.token, "a-jwt");

        let store: KeyStore<TestKeySlotIds> = KeyStore::default();
        state
            .encryption_key
            .install(&mut store.context_mut(), TestSymmSlotId::Organization)
            .unwrap();

        #[allow(deprecated)]
        let installed = store
            .context()
            .dangerous_get_symmetric_key(TestSymmSlotId::Organization)
            .unwrap()
            .to_base64();
        assert_eq!(
            installed,
            bitwarden_encoding::B64::from([7u8; 64].as_slice())
        );
    }

    #[test]
    fn set_then_get_round_trips_through_a_real_file() {
        let path = state_file_path();
        let access_token = access_token();

        let issuer_store: KeyStore<TestKeySlotIds> = KeyStore::default();
        let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        #[allow(deprecated)]
        issuer_store
            .context_mut()
            .set_symmetric_key(TestSymmSlotId::Organization, org_key.clone())
            .expect("set_symmetric_key");
        let exported_key =
            ExportedKey::from_slot(&issuer_store.context(), TestSymmSlotId::Organization).unwrap();

        let state = ClientState::new("a-jwt".to_string(), exported_key);
        set(&path, &access_token, &state).unwrap();
        let read_back = get(&path, &access_token).unwrap();
        std::fs::remove_file(&path).unwrap();

        assert_eq!(read_back.token, "a-jwt");

        let holder_store: KeyStore<TestKeySlotIds> = KeyStore::default();
        read_back
            .encryption_key
            .install(
                &mut holder_store.context_mut(),
                TestSymmSlotId::Organization,
            )
            .unwrap();

        let ctx = holder_store.context();
        #[allow(deprecated)]
        let installed = ctx
            .dangerous_get_symmetric_key(TestSymmSlotId::Organization)
            .unwrap();
        assert_eq!(installed.to_base64(), org_key.to_base64());
    }
}
