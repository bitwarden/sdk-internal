//! Key store keyed by kid, scheme dispatch, and keyset topological decrypt.

use std::collections::{HashMap, VecDeque};

use serde::de::DeserializeOwned;

use super::{
    account_key::AccountKey,
    error::OnePasswordError,
    kdf,
    opdata::{AesKey, Encrypted, decode64_loose},
    rsa::RsaKey,
    wire::{AesKeyJson, EncryptedEnvelope, KeysetInfo, KeysetsInfo, RsaKeyJwk},
};

const AES_SCHEME: &str = "A256GCM";
const RSA_SCHEMES: [&str; 2] = ["RSA-OAEP", "RSA-OAEP-256"];
const MASTER_KEY_ID: &str = "mp";

/// A store of AES and RSA keys keyed by their kid.
#[derive(Default)]
pub struct Keychain {
    aes: HashMap<String, AesKey>,
    rsa: HashMap<String, RsaKey>,
}

impl Keychain {
    pub fn new() -> Keychain {
        Keychain::default()
    }

    pub fn add_aes(&mut self, key: AesKey) {
        self.aes.insert(key.id.clone(), key);
    }

    pub fn add_rsa(&mut self, key: RsaKey) {
        self.rsa.insert(key.id.clone(), key);
    }

    #[cfg(test)]
    fn get_aes(&self, id: &str) -> Option<&AesKey> {
        self.aes.get(id)
    }

    #[cfg(test)]
    fn get_rsa(&self, id: &str) -> Option<&RsaKey> {
        self.rsa.get(id)
    }

    /// Decrypts an envelope by dispatching on its scheme to the AES or RSA key named by its kid.
    pub fn decrypt(&self, encrypted: &Encrypted) -> Result<Vec<u8>, OnePasswordError> {
        if encrypted.scheme == AES_SCHEME {
            let key = self.aes.get(&encrypted.key_id).ok_or_else(|| {
                OnePasswordError::Internal(format!("AES key '{}' not found", encrypted.key_id))
            })?;
            return key.decrypt(encrypted);
        }

        if RSA_SCHEMES.contains(&encrypted.scheme.as_str()) {
            let key = self.rsa.get(&encrypted.key_id).ok_or_else(|| {
                OnePasswordError::Internal(format!("RSA key '{}' not found", encrypted.key_id))
            })?;
            return key.decrypt(encrypted);
        }

        Err(OnePasswordError::Unsupported(format!(
            "Encryption scheme '{}' is not supported",
            encrypted.scheme
        )))
    }

    /// Whether the keychain currently holds the key needed to decrypt this envelope.
    ///
    /// A scheme this module does not implement is an error, not a `false`: the caller cannot tell
    /// "we lack the key" from "we cannot read this format" otherwise, and would silently drop data.
    pub fn can_decrypt(&self, encrypted: &Encrypted) -> Result<bool, OnePasswordError> {
        if encrypted.scheme == AES_SCHEME {
            return Ok(self.aes.contains_key(&encrypted.key_id));
        }

        if RSA_SCHEMES.contains(&encrypted.scheme.as_str()) {
            return Ok(self.rsa.contains_key(&encrypted.key_id));
        }

        Err(OnePasswordError::Unsupported(format!(
            "Encryption scheme '{}' is not supported",
            encrypted.scheme
        )))
    }

    /// Decrypts an envelope and parses its JSON plaintext.
    pub fn decrypt_json<T: DeserializeOwned>(
        &self,
        envelope: &EncryptedEnvelope,
    ) -> Result<T, OnePasswordError> {
        let plaintext = self.decrypt(&Encrypted::parse(envelope)?)?;
        serde_json::from_slice(&plaintext).map_err(|_| OnePasswordError::Parse)
    }

    /// Derives the master key from the credentials, then decrypts every keyset into the keychain.
    pub fn decrypt_keysets(
        &mut self,
        keysets: &[KeysetInfo],
        username: &str,
        password: &str,
        account_key: &AccountKey,
    ) -> Result<(), OnePasswordError> {
        let master_key = derive_master_key(keysets, username, password, account_key)?;
        self.decrypt_reachable(keysets, master_key)
    }

    /// Seeds `root_key` and decrypts everything reachable from it.
    fn decrypt_reachable(
        &mut self,
        keysets: &[KeysetInfo],
        root_key: AesKey,
    ) -> Result<(), OnePasswordError> {
        let order = decryption_order(keysets, &root_key.id);
        self.add_aes(root_key);

        for index in order {
            self.decrypt_keyset(&keysets[index])?;
        }

        Ok(())
    }

    /// Decrypts a keyset's symmetric key then its private key into the keychain.
    fn decrypt_keyset(&mut self, keyset: &KeysetInfo) -> Result<(), OnePasswordError> {
        self.decrypt_aes_key(&keyset.enc_sym_key.envelope())?;
        self.decrypt_rsa_key(&keyset.enc_pri_key)
    }

    /// Decrypts an encrypted AES key and adds it to the keychain.
    pub fn decrypt_aes_key(
        &mut self,
        envelope: &EncryptedEnvelope,
    ) -> Result<(), OnePasswordError> {
        let plaintext = self.decrypt(&Encrypted::parse(envelope)?)?;
        let json: AesKeyJson =
            serde_json::from_slice(&plaintext).map_err(|_| OnePasswordError::Parse)?;
        self.add_aes(AesKey::new(json.kid, decode64_loose(&json.k)?));
        Ok(())
    }

    /// Decrypts an encrypted RSA key and adds it to the keychain.
    fn decrypt_rsa_key(&mut self, envelope: &EncryptedEnvelope) -> Result<(), OnePasswordError> {
        let plaintext = self.decrypt(&Encrypted::parse(envelope)?)?;
        let jwk: RsaKeyJwk =
            serde_json::from_slice(&plaintext).map_err(|_| OnePasswordError::Parse)?;
        self.add_rsa(RsaKey::parse(&jwk)?);
        Ok(())
    }
}

/// Derives the key of the newest master keyset, the only one carrying KDF parameters.
fn derive_master_key(
    keysets: &[KeysetInfo],
    username: &str,
    password: &str,
    account_key: &AccountKey,
) -> Result<AesKey, OnePasswordError> {
    let master = keysets
        .iter()
        .filter(|k| k.encrypted_by == MASTER_KEY_ID)
        .max_by_key(|k| k.sn)
        .ok_or_else(|| OnePasswordError::Internal("Master keyset not found".into()))?;

    let info = &master.enc_sym_key;
    let algorithm = info.alg.as_deref().ok_or_else(|| {
        OnePasswordError::Internal("master keyset is missing the algorithm".into())
    })?;
    let salt =
        decode64_loose(info.p2s.as_deref().ok_or_else(|| {
            OnePasswordError::Internal("master keyset is missing the salt".into())
        })?)?;
    // `pbkdf2` runs `1..rounds`, so a missing count would stretch the password exactly once.
    if info.p2c == 0 {
        return Err(OnePasswordError::Internal(
            "master keyset is missing the iteration count".into(),
        ));
    }
    let key = kdf::derive_master_key(algorithm, info.p2c, &salt, username, password, account_key)?;

    Ok(AesKey::new(MASTER_KEY_ID, key.to_vec()))
}

/// Orders keysets so each one comes after the key that encrypts it, starting from `root_id`.
/// Keysets the root cannot reach are left out.
fn decryption_order(keysets: &[KeysetInfo], root_id: &str) -> Vec<usize> {
    let mut encrypts: HashMap<&str, Vec<usize>> = HashMap::new();
    for (index, keyset) in keysets.iter().enumerate() {
        encrypts
            .entry(encrypted_by(keyset))
            .or_default()
            .push(index);
    }

    // Visit each keyset once, tracked by position: an entry whose encrypter resolves to its own
    // uuid would re-enqueue forever, and uuids repeat in real responses.
    let mut visited = vec![false; keysets.len()];
    let mut queue: VecDeque<usize> = encrypts.get(root_id).cloned().unwrap_or_default().into();
    let mut order = Vec::with_capacity(keysets.len());
    while let Some(index) = queue.pop_front() {
        if std::mem::replace(&mut visited[index], true) {
            continue;
        }

        order.push(index);
        if let Some(children) = encrypts.get(keysets[index].uuid.as_str()) {
            queue.extend(children);
        }
    }

    order
}

/// The key id that encrypts a keyset: its explicit `encryptedBy`, or the symmetric key's kid when
/// that is empty.
fn encrypted_by(keyset: &KeysetInfo) -> &str {
    if keyset.encrypted_by.is_empty() {
        &keyset.enc_sym_key.kid
    } else {
        &keyset.encrypted_by
    }
}

#[cfg(test)]
mod tests {
    use data_encoding::HEXLOWER;

    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        HEXLOWER.decode(s.as_bytes()).expect("valid hex")
    }

    #[test]
    fn decrypt_aes_key_adds_key_to_keychain() {
        let mut keychain = Keychain::new();
        keychain.add_aes(AesKey::new(
            "mp",
            hex("44c38e8fedb84a1ab5ba74ed98dde931f6500ae39c1d9c85e20a7268ab2074f0"),
        ));

        let envelope: EncryptedEnvelope =
            serde_json::from_str(include_str!("resources/encrypted-aes-key.json"))
                .expect("valid fixture");
        keychain.decrypt_aes_key(&envelope).expect("decrypts");

        assert!(keychain.get_aes("szerdhg2ww2ahjo4ilz57x7cce").is_some());
    }

    #[test]
    fn decrypt_rsa_key_adds_key_to_keychain() {
        let mut keychain = Keychain::new();
        keychain.add_aes(AesKey::new(
            "szerdhg2ww2ahjo4ilz57x7cce",
            hex("bba932f6032dc4dffaa9b8f03c9fd4b810127b89a49408db7b914a131690c091"),
        ));

        let envelope: EncryptedEnvelope =
            serde_json::from_str(include_str!("resources/encrypted-rsa-key.json"))
                .expect("valid fixture");
        keychain.decrypt_rsa_key(&envelope).expect("decrypts");

        assert!(keychain.get_rsa("szerdhg2ww2ahjo4ilz57x7cce").is_some());
    }

    #[test]
    fn decrypt_keysets_decrypts_all_keys() {
        let keysets: KeysetsInfo =
            serde_json::from_str(include_str!("resources/get-keysets-response.json"))
                .expect("valid fixture");
        let mut keychain = Keychain::new();

        // This fixture's master keyset carries a `p2s` that no longer matches its encrypted data,
        // so the walk starts from the master key directly (the derivation is pinned by the kdf
        // vector).
        let master_key = AesKey::new(
            MASTER_KEY_ID,
            hex("44c38e8fedb84a1ab5ba74ed98dde931f6500ae39c1d9c85e20a7268ab2074f0"),
        );
        keychain
            .decrypt_reachable(&keysets.keysets, master_key)
            .expect("decrypts keysets");

        assert!(keychain.get_aes("mp").is_some());
        for id in [
            "szerdhg2ww2ahjo4ilz57x7cce",
            "yf2ji37vkqdow7pnbo3y37b3lu",
            "srkx3r5c3qgyzsdswfc4awgh2m",
            "sm5hkw3mxwdcwcgljf4kyplwea",
        ] {
            assert!(keychain.get_aes(id).is_some(), "missing AES key {id}");
            assert!(keychain.get_rsa(id).is_some(), "missing RSA key {id}");
        }
    }

    fn keyset(uuid: &str, encrypted_by: &str) -> KeysetInfo {
        serde_json::from_value(serde_json::json!({
            "uuid": uuid,
            "encryptedBy": encrypted_by,
            "sn": 1,
            "encSymKey": {"kid": encrypted_by, "enc": AES_SCHEME, "cty": "b5+jwk+json", "data": ""},
            "encPriKey": {"kid": encrypted_by, "enc": AES_SCHEME, "cty": "b5+jwk+json", "data": ""},
        }))
        .expect("valid keyset")
    }

    #[test]
    fn decryption_order_follows_the_chain_from_the_root() {
        let keysets = [
            keyset("c", "b"),
            keyset("a", MASTER_KEY_ID),
            keyset("b", "a"),
            keyset("orphan", "nobody"),
        ];

        // Every keyset comes after the one that encrypts it, and what the root cannot reach is
        // left out.
        assert_eq!(decryption_order(&keysets, MASTER_KEY_ID), vec![1, 2, 0]);
    }

    #[test]
    fn decryption_order_visits_a_self_referential_keyset_once() {
        // A keyset naming itself as its encrypter would re-enqueue forever, so a regression here
        // hangs rather than fails.
        let keysets = [keyset("a", MASTER_KEY_ID), keyset("a", "a")];

        assert_eq!(decryption_order(&keysets, MASTER_KEY_ID), vec![0, 1]);
    }

    #[test]
    fn decrypt_rejects_unknown_scheme() {
        let keychain = Keychain::new();
        let encrypted = Encrypted {
            key_id: "mp".into(),
            scheme: "A128CBC".into(),
            iv: Vec::new(),
            ciphertext: Vec::new(),
        };

        let err = keychain
            .can_decrypt(&encrypted)
            .expect_err("unsupported scheme");
        assert!(matches!(err, OnePasswordError::Unsupported(_)));

        let err = keychain
            .decrypt(&encrypted)
            .expect_err("unsupported scheme");
        assert!(matches!(err, OnePasswordError::Unsupported(_)));
    }
}
