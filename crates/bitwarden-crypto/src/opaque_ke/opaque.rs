use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, Identifiers, RegistrationRequest, RegistrationResponse, RegistrationUpload,
    ServerLogin, ServerLoginStartParameters, ServerRegistration, ServerSetup,
};

use super::types::{self, Argon2Id, CipherConfiguration, KeGroup, KeyExchange, Ksf, OprfCs};

type Error = super::error::OpaqueError;

pub trait OpaqueImpl {
    fn start_client_registration(
        &self,
        password: &str,
    ) -> Result<types::ClientRegistrationStartResult, Error>;
    fn start_server_registration(
        &self,
        server_setup: Option<&[u8]>,
        registration_request: &[u8],
        username: &str,
    ) -> Result<types::ServerRegistrationStartResult, Error>;
    fn finish_client_registration(
        &self,
        state: &[u8],
        registration_response: &[u8],
        password: &str,
    ) -> Result<types::ClientRegistrationFinishResult, Error>;
    fn finish_server_registration(
        &self,
        registration_upload: &[u8],
    ) -> Result<types::ServerRegistrationFinishResult, Error>;

    fn start_client_login(&self, password: &str) -> Result<types::ClientLoginStartResult, Error>;
    fn start_server_login(
        &self,
        server_setup: &[u8],
        server_registration: &[u8],
        credential_request: &[u8],
        username: &str,
    ) -> Result<types::ServerLoginStartResult, Error>;
    fn finish_client_login(
        &self,
        state: &[u8],
        credential_response: &[u8],
        password: &str,
    ) -> Result<types::ClientLoginFinishResult, Error>;
    fn finish_server_login(
        &self,
        state: &[u8],
        credential_finalization: &[u8],
    ) -> Result<types::ServerLoginFinishResult, Error>;
}

// This trait exists to extract the differences between all the OpaqueImpl implementations.
// This would allow replacing those impls by a macro in the future.
pub trait OpaqueUtil: Sized {
    type Output;
    fn as_variant(config: &CipherConfiguration) -> Option<Self>;
    fn get_ksf(&self) -> Result<Self::Output, Error>;
}

// Implement the OpaqueImpl trait for the CipherConfiguration enum, which allows us to dynamically
// dispatch to the correct cipher suite.
impl OpaqueImpl for CipherConfiguration {
    fn start_client_registration(
        &self,
        password: &str,
    ) -> Result<types::ClientRegistrationStartResult, Error> {
        if let Some(suite) = RistrettoTripleDhArgonSuite::as_variant(self) {
            return suite.start_client_registration(password);
        };
        Err(Error::InvalidInput(
            "Invalid cipher configuration".to_string(),
        ))
    }
    fn start_server_registration(
        &self,
        server_setup: Option<&[u8]>,
        registration_request: &[u8],
        username: &str,
    ) -> Result<types::ServerRegistrationStartResult, Error> {
        if let Some(suite) = RistrettoTripleDhArgonSuite::as_variant(self) {
            return suite.start_server_registration(server_setup, registration_request, username);
        };
        Err(Error::InvalidInput(
            "Invalid cipher configuration".to_string(),
        ))
    }
    fn finish_client_registration(
        &self,
        state: &[u8],
        registration_response: &[u8],
        password: &str,
    ) -> Result<types::ClientRegistrationFinishResult, Error> {
        if let Some(suite) = RistrettoTripleDhArgonSuite::as_variant(self) {
            return suite.finish_client_registration(state, registration_response, password);
        };
        Err(Error::InvalidInput(
            "Invalid cipher configuration".to_string(),
        ))
    }
    fn finish_server_registration(
        &self,
        registration_upload: &[u8],
    ) -> Result<types::ServerRegistrationFinishResult, Error> {
        if let Some(suite) = RistrettoTripleDhArgonSuite::as_variant(self) {
            return suite.finish_server_registration(registration_upload);
        };
        Err(Error::InvalidInput(
            "Invalid cipher configuration".to_string(),
        ))
    }

    fn start_client_login(&self, password: &str) -> Result<types::ClientLoginStartResult, Error> {
        if let Some(suite) = RistrettoTripleDhArgonSuite::as_variant(self) {
            return suite.start_client_login(password);
        };
        Err(Error::InvalidInput(
            "Invalid cipher configuration".to_string(),
        ))
    }
    fn start_server_login(
        &self,
        server_setup: &[u8],
        server_registration: &[u8],
        credential_request: &[u8],
        username: &str,
    ) -> Result<types::ServerLoginStartResult, Error> {
        if let Some(suite) = RistrettoTripleDhArgonSuite::as_variant(self) {
            return suite.start_server_login(
                server_setup,
                server_registration,
                credential_request,
                username,
            );
        };
        Err(Error::InvalidInput(
            "Invalid cipher configuration".to_string(),
        ))
    }
    fn finish_client_login(
        &self,
        state: &[u8],
        credential_response: &[u8],
        password: &str,
    ) -> Result<types::ClientLoginFinishResult, Error> {
        if let Some(suite) = RistrettoTripleDhArgonSuite::as_variant(self) {
            return suite.finish_client_login(state, credential_response, password);
        };
        Err(Error::InvalidInput(
            "Invalid cipher configuration".to_string(),
        ))
    }
    fn finish_server_login(
        &self,
        state: &[u8],
        credential_finalization: &[u8],
    ) -> Result<types::ServerLoginFinishResult, Error> {
        if let Some(suite) = RistrettoTripleDhArgonSuite::as_variant(self) {
            return suite.finish_server_login(state, credential_finalization);
        };
        Err(Error::InvalidInput(
            "Invalid cipher configuration".to_string(),
        ))
    }
}

// Define the cipher suite and implement the required traits on it
// (opaque_ke::CipherSuite+OpaqueUtil+OpaqueImpl)
struct RistrettoTripleDhArgonSuite(Argon2Id);
impl opaque_ke::CipherSuite for RistrettoTripleDhArgonSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = Argon2Id;
}
impl OpaqueUtil for RistrettoTripleDhArgonSuite {
    type Output = Argon2Id;

    fn as_variant(config: &CipherConfiguration) -> Option<Self> {
        match config {
            CipherConfiguration {
                oprf_cs: OprfCs::Ristretto255,
                ke_group: KeGroup::Ristretto255,
                key_exchange: KeyExchange::TripleDh,
                ksf: Ksf::Argon2id(memory_kib, iterations, parallelism),
            } => Some(Self(Argon2Id {
                memory_kib: *memory_kib,
                iterations: *iterations,
                parallelism: *parallelism,
            })),
        }
    }
    fn get_ksf(&self) -> Result<Self::Output, Error> {
        Ok(self.0.clone())
    }
}

// This implementation will be identical between any cipher suite, but we can't simply reuse it
// because of all the generic bounds on the CipherSuite trait. If we need to add more cipher suites,
// we will need to copy this implementation over, or ideally use a macro to generate it.
impl OpaqueImpl for RistrettoTripleDhArgonSuite {
    fn start_client_registration(
        &self,
        password: &str,
    ) -> Result<types::ClientRegistrationStartResult, Error> {
        let result =
            ClientRegistration::<Self>::start(&mut rand::thread_rng(), password.as_bytes())?;
        Ok(types::ClientRegistrationStartResult {
            registration_request: result.message.serialize().to_vec().into(),
            state: result.state.serialize().to_vec().into(),
        })
    }
    fn start_server_registration(
        &self,
        server_setup: Option<&[u8]>,
        registration_request: &[u8],
        username: &str,
    ) -> Result<types::ServerRegistrationStartResult, Error> {
        let server_setup = match server_setup {
            Some(server_setup) => ServerSetup::<Self>::deserialize(server_setup)?,
            None => ServerSetup::<Self>::new(&mut rand::thread_rng()),
        };
        let result = ServerRegistration::start(
            &server_setup,
            RegistrationRequest::deserialize(registration_request)?,
            username.as_bytes(),
        )?;
        Ok(types::ServerRegistrationStartResult {
            registration_response: result.message.serialize().to_vec(),
            server_setup: server_setup.serialize().to_vec(),
        })
    }
    fn finish_client_registration(
        &self,
        state: &[u8],
        registration_response: &[u8],
        password: &str,
    ) -> Result<types::ClientRegistrationFinishResult, Error> {
        let state = ClientRegistration::<Self>::deserialize(state)?;
        let result = state.finish(
            &mut rand::thread_rng(),
            password.as_bytes(),
            RegistrationResponse::deserialize(registration_response)?,
            ClientRegistrationFinishParameters::new(Identifiers::default(), Some(&self.get_ksf()?)),
        )?;
        Ok(types::ClientRegistrationFinishResult {
            registration_upload: result.message.serialize().to_vec().into(),
            export_key: result.export_key.to_vec().into(),
            server_public_key: result.server_s_pk.serialize().to_vec().into(),
        })
    }
    fn finish_server_registration(
        &self,
        registration_upload: &[u8],
    ) -> Result<types::ServerRegistrationFinishResult, Error> {
        let registration = ServerRegistration::finish(RegistrationUpload::<Self>::deserialize(
            registration_upload,
        )?);
        Ok(types::ServerRegistrationFinishResult {
            server_registration: registration.serialize().to_vec(),
        })
    }

    fn start_client_login(&self, password: &str) -> Result<types::ClientLoginStartResult, Error> {
        let result = ClientLogin::<Self>::start(&mut rand::thread_rng(), password.as_bytes())?;
        Ok(types::ClientLoginStartResult {
            credential_request: result.message.serialize().to_vec().into(),
            state: result.state.serialize().to_vec().into(),
        })
    }
    fn start_server_login(
        &self,
        server_setup: &[u8],
        server_registration: &[u8],
        credential_request: &[u8],
        username: &str,
    ) -> Result<types::ServerLoginStartResult, Error> {
        let result = ServerLogin::start(
            &mut rand::thread_rng(),
            &ServerSetup::<Self>::deserialize(server_setup)?,
            Some(ServerRegistration::<Self>::deserialize(
                server_registration,
            )?),
            CredentialRequest::deserialize(credential_request)?,
            username.as_bytes(),
            ServerLoginStartParameters::default(),
        )?;
        Ok(types::ServerLoginStartResult {
            credential_response: result.message.serialize().to_vec(),
            state: result.state.serialize().to_vec(),
        })
    }
    fn finish_client_login(
        &self,
        state: &[u8],
        credential_response: &[u8],
        password: &str,
    ) -> Result<types::ClientLoginFinishResult, Error> {
        let client_login = ClientLogin::<Self>::deserialize(state)?;
        let result = client_login.finish(
            password.as_bytes(),
            CredentialResponse::deserialize(credential_response)?,
            ClientLoginFinishParameters::new(None, Identifiers::default(), Some(&self.get_ksf()?)),
        )?;
        Ok(types::ClientLoginFinishResult {
            credential_finalization: result.message.serialize().to_vec().into(),
            session_key: result.session_key.to_vec().into(),
            export_key: result.export_key.to_vec().into(),
            server_public_key: result.server_s_pk.serialize().to_vec().into(),
        })
    }
    fn finish_server_login(
        &self,
        state: &[u8],
        credential_finalization: &[u8],
    ) -> Result<types::ServerLoginFinishResult, Error> {
        let server_login = ServerLogin::<Self>::deserialize(state)?;
        let result = server_login.finish(CredentialFinalization::deserialize(
            credential_finalization,
        )?)?;
        Ok(types::ServerLoginFinishResult {
            session_key: result.session_key.to_vec(),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::opaque_ke::opaque::types::CipherConfiguration;

    #[test]
    fn test_opaque_register() {
        let mut server = crate::opaque_ke::mock_server::MockServer::new();
        let config = CipherConfiguration {
            oprf_cs: OprfCs::Ristretto255,
            ke_group: KeGroup::Ristretto255,
            key_exchange: KeyExchange::TripleDh,
            ksf: Ksf::Argon2id(65536, 1, 1),
        };

        // register
        let password = "password";
        let registration_start = config.start_client_registration(password).unwrap();
        let (registration_start_response, id) = server
            .register_start(&registration_start.registration_request, config.clone())
            .unwrap();
        let registration_finish = config
            .finish_client_registration(
                &registration_start.state,
                registration_start_response.as_slice(),
                password,
            )
            .unwrap();
        server.register_finish(&registration_finish.registration_upload, id, config.clone());

        // login
        let login_start = config.start_client_login(password).unwrap();
        let login_start_response =
            server.login_start(&login_start.credential_request, id, config.clone());
        let login_finish_client = config
            .finish_client_login(&login_start.state, &login_start_response, password)
            .unwrap();
        let session_key_server = server.login_finish(
            &login_finish_client.credential_finalization,
            id,
            config.clone(),
        );

        assert_eq!(session_key_server, login_finish_client.session_key.to_vec())
    }
}
