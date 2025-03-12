use argon2::Params;
use generic_array::{typenum::U32, ArrayLength, GenericArray};
use opaque_ke::{
    errors::InternalError, ksf::Ksf, CipherSuite, ClientLogin, ClientLoginFinishParameters,
    ClientRegistration, ClientRegistrationFinishParameters, CredentialResponse, Identifiers,
    RegistrationResponse,
};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify_next::Tsify;

use crate::{
    error::OpaqueError, rotateable_keyset::RotateableKeyset, stretch_key, SymmetricCryptoKey,
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
            Params::new(self.m_cost, self.t_cost, self.p_cost, Some(64))
                .map_err(|_| InternalError::KsfError)?,
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

    let sliced_export_key = Box::pin(*GenericArray::from_slice(
        &client_registration.export_key.as_slice()[..32],
    ));
    let stretched_export_key = SymmetricCryptoKey::Aes256CbcHmacKey(
        stretch_key(&sliced_export_key)
            .map_err(|_| OpaqueError::Message("Failed stretching export key".to_string()))?,
    );

    let keyset = RotateableKeyset::new(&stretched_export_key, &userkey)
        .map_err(|e| OpaqueError::Message(e.to_string()))?;
    Ok(RegistrationFinishResult {
        registration_finish_message: client_registration.message.serialize().to_vec(),
        keyset,
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
    /// The client-side only export key result from the AKE. Note: This is limited to 256 bits,
    /// if the cipher parameters have a larger key size, the key will be truncated.
    pub export_key: GenericArray<u8, U32>,
    #[serde(with = "serde_bytes")]
    pub session_key: Vec<u8>,
}

pub fn login_finish(
    login_start_state: &[u8],
    login_start_response: &[u8],
    password: &[u8],
    cipher_config: &CipherConfiguration,
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

    Ok(LoginFinishResult {
        login_finish_result_message: client_login.message.serialize().to_vec(),
        // ristretto255 uses sha512, but we want to deal with 256 bit keys
        export_key: *GenericArray::from_slice(&client_login.export_key.as_slice()[..32]),
        session_key: client_login.session_key.to_vec(),
    })
}

#[cfg(test)]
mod test {
    use opaque_ke::{
        CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
        ServerLogin, ServerLoginStartParameters, ServerRegistration, ServerSetup,
    };

    use super::*;
    use crate::SymmetricCryptoKey;

    struct MockServer {
        server_setup: Option<ServerSetup<CipherConfiguration>>,
        password_file: Option<Vec<u8>>,
        server_login_state: Option<Vec<u8>>,
    }

    impl MockServer {
        fn new() -> Self {
            MockServer {
                server_setup: None,
                password_file: None,
                server_login_state: None,
            }
        }

        fn register_start(
            &mut self,
            register_start_message: &[u8],
        ) -> Result<Vec<u8>, OpaqueError> {
            let server_setup = ServerSetup::<CipherConfiguration>::new(&mut rand::thread_rng());
            self.server_setup = Some(server_setup.clone());
            let registration = ServerRegistration::<CipherConfiguration>::start(
                &server_setup,
                RegistrationRequest::deserialize(&register_start_message).unwrap(),
                "username".as_bytes(),
            )
            .unwrap();
            Ok(registration.message.serialize().to_vec())
        }

        fn register_finish(&mut self, register_finish_message: &[u8]) -> Result<(), OpaqueError> {
            let password_file = ServerRegistration::finish(
                RegistrationUpload::<CipherConfiguration>::deserialize(&register_finish_message)
                    .unwrap(),
            );
            self.password_file = Some(password_file.serialize().to_vec());
            Ok(())
        }

        fn login_start(&mut self, login_start_message: &[u8]) -> Result<Vec<u8>, OpaqueError> {
            let server_setup = self.server_setup.as_ref().unwrap();
            let login = ServerLogin::<CipherConfiguration>::start(
                &mut rand::thread_rng(),
                server_setup,
                Some(
                    ServerRegistration::deserialize(&self.password_file.as_ref().unwrap()).unwrap(),
                ),
                CredentialRequest::deserialize(login_start_message).unwrap(),
                "username".as_bytes(),
                ServerLoginStartParameters::default(),
            )
            .unwrap();
            self.server_login_state = Some(login.state.serialize().to_vec());

            Ok(login.message.serialize().to_vec())
        }

        fn login_finish(&self, login_finish_message: &[u8]) -> Result<Vec<u8>, OpaqueError> {
            let login_start = ServerLogin::<CipherConfiguration>::deserialize(
                &self.server_login_state.as_ref().unwrap(),
            )
            .unwrap();
            let login = login_start
                .finish(CredentialFinalization::deserialize(login_finish_message).unwrap())
                .unwrap();
            Ok(login.session_key.to_vec())
        }
    }

    #[test]
    fn test_opaque_register() {
        let mut server = MockServer::new();

        let password = b"password";
        let registration_start = register_start(password).unwrap();
        let registration_finish = server
            .register_start(&registration_start.registration_start_message)
            .unwrap();
        let initial_userkey = SymmetricCryptoKey::generate(&mut rand::thread_rng());
        let registration_finish = register_finish(
            &registration_start.registration_start_state,
            &registration_finish,
            password,
            &CipherConfiguration {
                oprf: OprfCS::Ristretto255,
                ke_group: KeGroup::Ristretto255,
                key_exchange: KeyExchange::TripleDH,
                ksf: Argon2Id {
                    t_cost: 1,
                    m_cost: 65536,
                    p_cost: 1,
                },
            },
            initial_userkey.clone(),
        )
        .unwrap();
        server
            .register_finish(&registration_finish.registration_finish_message)
            .unwrap();

        let login_start = login_start(password).unwrap();
        let login_finish_message = server
            .login_start(&login_start.login_start_message)
            .unwrap();
        let login_finish = login_finish(
            &login_start.login_start_state,
            &login_finish_message,
            password,
            &CipherConfiguration {
                oprf: OprfCS::Ristretto255,
                ke_group: KeGroup::Ristretto255,
                key_exchange: KeyExchange::TripleDH,
                ksf: Argon2Id {
                    t_cost: 1,
                    m_cost: 65536,
                    p_cost: 1,
                },
            },
        )
        .unwrap();

        let stretched_export_key = SymmetricCryptoKey::Aes256CbcHmacKey(
            stretch_key(&Box::pin(login_finish.export_key)).unwrap(),
        );
        let authentication_userkey = registration_finish
            .keyset
            .decrypt_encapsulated_key(&stretched_export_key)
            .unwrap();
        assert_eq!(initial_userkey, authentication_userkey);

        let session_key = server
            .login_finish(&login_finish.login_finish_result_message)
            .unwrap();
        assert_eq!(login_finish.session_key, session_key);
    }
}
