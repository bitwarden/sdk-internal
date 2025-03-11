use argon2::Params;
use generic_array::{ArrayLength, GenericArray};
use opaque_ke::{
    errors::InternalError, ksf::Ksf, CipherSuite, ClientLogin, ClientLoginFinishParameters,
    ClientRegistration, ClientRegistrationFinishParameters, CredentialResponse, Identifiers,
    RegistrationResponse,
};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify_next::Tsify;

use crate::{
    error::OpaqueError, keys, rotateable_keyset::RotateableKeyset, SymmetricCryptoKey
};

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum OprfCS {
    #[serde(rename = "ristretto255")]
    Ristretto255,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum KeGroup {
    #[serde(rename = "ristretto255")]
    Ristretto255,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum KeyExchange {
    #[serde(rename = "triple-dh")]
    TripleDH,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum KSF {
    #[serde(rename = "argon2id")]
    Argon2id(u32, u32, u32),
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct CipherConfiguration {
    pub oprf: OprfCS,
    pub ke_group: KeGroup,
    pub key_exchange: KeyExchange,
    pub ksf: Argon2Id,
}

impl CipherSuite for CipherConfiguration {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = Argon2Id;
}

#[derive(Serialize, Deserialize, Default)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct Argon2Id {
    t_cost: u32,
    m_cost: u32,
    p_cost: u32,
}

impl Ksf for Argon2Id {
    fn hash<L: ArrayLength<u8>>(
        &self,
        input: GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, L>, InternalError> {
        let mut output = GenericArray::default();
        let res = argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            Params::new(self.m_cost, self.t_cost, self.p_cost, Some(32)).unwrap(),
        );
        res.hash_password_into(&input, &[0; argon2::RECOMMENDED_SALT_LEN], &mut output)
            .map_err(|_| InternalError::KsfError)?;
        Ok(output)
    }
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct RegistrationStartResult {
    #[serde(with = "serde_bytes")]
    pub registration_start_state: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub registration_start_message: Vec<u8>,
}

pub fn register_start(password: &[u8]) -> Result<RegistrationStartResult, OpaqueError> {
    let registration_start_result =
        ClientRegistration::<CipherConfiguration>::start(&mut rand::thread_rng(), password)
            .map_err(|e| OpaqueError::Message(e.to_string()))?;
    let state = registration_start_result.state.serialize().to_vec();
    let message = registration_start_result.message.serialize().to_vec();
    Ok(RegistrationStartResult {
        registration_start_state: state,
        registration_start_message: message,
    })
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct RegistrationFinishResult {
    #[serde(with = "serde_bytes")]
    pub registration_finish_message: Vec<u8>,
    pub keyset: RotateableKeyset,
}

pub fn register_finish(
    registration_start_state: &[u8],
    registration_start_response: &[u8],
    password: &[u8],
    cipher_config: &CipherConfiguration,
    userkey: SymmetricCryptoKey,
) -> Result<RegistrationFinishResult, OpaqueError> {
    let start_message =
        ClientRegistration::<CipherConfiguration>::deserialize(registration_start_state)
            .map_err(|_| OpaqueError::Deserialize)?;
    let ksf = Argon2Id {
        t_cost: cipher_config.ksf.t_cost,
        m_cost: cipher_config.ksf.m_cost,
        p_cost: cipher_config.ksf.p_cost,
    };
    let params = ClientRegistrationFinishParameters::new(Identifiers::default(), Some(&ksf));
    let client_registration = start_message
        .finish(
            &mut rand::thread_rng(),
            password,
            RegistrationResponse::deserialize(registration_start_response)
                .map_err(|_| OpaqueError::Deserialize)?,
            params,
        )
        .map_err(|e| OpaqueError::Message(e.to_string()))?;

    let stretched_export_key = SymmetricCryptoKey::Aes256CbcHmacKey(
        keys::stretch_key(&Box::pin(*GenericArray::from_slice(
            &client_registration.export_key,
        )))
        .map_err(|_| OpaqueError::Message("Error stretching key".to_string()))?,
    );
    let keyset = RotateableKeyset::new(&stretched_export_key, &userkey)
        .map_err(|e| OpaqueError::Message(e.to_string()))?;
    Ok(RegistrationFinishResult {
        registration_finish_message: client_registration.message.serialize().to_vec(),
        keyset: keyset,
    })
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct LoginStartResult {
    /// The serialized state of the started login attempt
    #[serde(with = "serde_bytes")]
    pub login_start_state: Vec<u8>,
    /// The serialized LoginStart message from the client to be sent to the server
    #[serde(with = "serde_bytes")]
    pub login_start_message: Vec<u8>,
}

pub fn login_start(password: &[u8]) -> Result<LoginStartResult, OpaqueError> {
    let login_start_result =
        ClientLogin::<CipherConfiguration>::start(&mut rand::thread_rng(), password)
            .map_err(|e| OpaqueError::Message(e.to_string()))?;
    Ok(LoginStartResult {
        login_start_state: login_start_result.state.serialize().to_vec(),
        login_start_message: login_start_result.message.serialize().to_vec(),
    })
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct LoginFinishResult {
    #[serde(with = "serde_bytes")]
    pub login_finish_result_message: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub user_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub session_key: Vec<u8>,
}

pub fn login_finish(
    login_start_state: &[u8],
    login_start_response: &[u8],
    password: &[u8],
    cipher_config: &CipherConfiguration,
    rotateable_keyset: RotateableKeyset,
) -> Result<LoginFinishResult, OpaqueError> {
    let start_message = ClientLogin::<CipherConfiguration>::deserialize(login_start_state)
        .map_err(|_| OpaqueError::Deserialize)?;
    let ksf = Argon2Id {
        t_cost: cipher_config.ksf.t_cost,
        m_cost: cipher_config.ksf.m_cost,
        p_cost: cipher_config.ksf.p_cost,
    };
    let params = ClientLoginFinishParameters::new(None, Identifiers::default(), Some(&ksf));
    let client_login = start_message
        .finish(
            password,
            CredentialResponse::deserialize(login_start_response)
                .map_err(|_| OpaqueError::Deserialize)?,
            params,
        )
        .map_err(|e| OpaqueError::Message(e.to_string()))?;

    let stretched_export_key = SymmetricCryptoKey::Aes256CbcHmacKey(
        keys::stretch_key(&Box::pin(*GenericArray::from_slice(
            &client_login.export_key,
        )))
        .map_err(|_| OpaqueError::Message("Error stretching key".to_string()))?,
    );
    let userkey = rotateable_keyset.decrypt_encapsulated_key(&stretched_export_key).map_err(|e| OpaqueError::Message(e.to_string()))?;

    Ok(LoginFinishResult {
        login_finish_result_message: client_login.message.serialize().to_vec(),
        user_key: userkey.to_vec(),
        session_key: client_login.session_key.to_vec(),
    })
}
