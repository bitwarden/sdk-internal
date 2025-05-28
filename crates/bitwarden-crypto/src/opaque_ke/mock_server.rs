use std::collections::HashMap;

use opaque_ke::ServerSetup;

use super::{
    opaque::OpaqueImpl,
    types::{CipherConfiguration, RistrettoTripleDhArgonSuite},
};
use crate::OpaqueError;

/// Mock opaque server implementation for testing purposes.
/// Stores server state and registrations in-memory
pub(crate) struct MockServer {
    server_setups: HashMap<u8, Vec<u8>>,
    password_files: HashMap<u8, Vec<u8>>,
    server_login_state: HashMap<u8, Vec<u8>>,
    id_counter: u8,
}

impl MockServer {
    pub(crate) fn new() -> Self {
        MockServer {
            server_setups: HashMap::new(),
            password_files: HashMap::new(),
            server_login_state: HashMap::new(),
            id_counter: 0,
        }
    }

    pub(crate) fn register_start(
        &mut self,
        register_start_message: &[u8],
        config: CipherConfiguration,
    ) -> Result<(Vec<u8>, u8), OpaqueError> {
        let id = self.id_counter;
        self.id_counter += 1;

        let server_setup = ServerSetup::<RistrettoTripleDhArgonSuite>::new(&mut rand::thread_rng())
            .serialize()
            .to_vec();
        let result = config
            .start_server_registration(Some(&server_setup), register_start_message, "username")
            .unwrap();
        self.server_setups.insert(id, server_setup);
        Ok((result.registration_response, id))
    }

    pub(crate) fn register_finish(
        &mut self,
        register_finish_message: &[u8],
        id: u8,
        config: CipherConfiguration,
    ) {
        let result = config
            .finish_server_registration(register_finish_message)
            .unwrap();
        self.password_files.insert(id, result.server_registration);
    }

    pub(crate) fn login_start(
        &mut self,
        login_start_message: &[u8],
        id: u8,
        config: CipherConfiguration,
    ) -> Vec<u8> {
        let login_state = config
            .start_server_login(
                self.server_setups.get(&id).unwrap(),
                self.password_files.get(&id).unwrap(),
                login_start_message,
                "username",
            )
            .unwrap();
        self.server_login_state.insert(id, login_state.state);
        login_state.credential_response
    }

    pub(crate) fn login_finish(
        &self,
        login_finish_message: &[u8],
        id: u8,
        config: CipherConfiguration,
    ) -> Vec<u8> {
        config
            .finish_server_login(
                self.server_login_state.get(&id).unwrap(),
                login_finish_message,
            )
            .unwrap()
            .session_key
    }
}
