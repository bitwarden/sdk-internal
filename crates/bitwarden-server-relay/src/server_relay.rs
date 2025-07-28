use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{hub_client::HubClient, initiator, messages::ProtocolPayload, responder};

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct ServerRelayResponderPreHandshake {
    websocket: crate::hub_client::WebsocketHubClient,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl ServerRelayResponderPreHandshake {
    pub async fn listen() -> Self {
        let client = responder::listen().await.unwrap();
        Self { websocket: client }
    }

    pub async fn wait_for_handshake(mut self, psk: Vec<u8>) -> ServerRelayResponder {
        let (encryptor, destination) = responder::handshake(&mut self.websocket, psk)
            .await
            .unwrap();
        ServerRelayResponder {
            websocket: self.websocket,
            encryptor,
            destination,
        }
    }

    pub async fn get_id(&self) -> Option<String> {
        self.websocket.local_uuid().map(|uuid| uuid.to_string())
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct ServerRelayResponder {
    websocket: crate::hub_client::WebsocketHubClient,
    encryptor: crate::payload_encryptor::PayloadEncryptor,
    destination: Uuid,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl ServerRelayResponder {
    pub async fn wait_for_auth_request(&mut self) -> AuthRequest {
        let message = self.websocket.receive_message().await.unwrap();
        let decrypted = self.encryptor.decrypt(message.message);
        match decrypted {
            ProtocolPayload::AuthRequest {
                userkey,
                email,
                auth_request_id,
            } => AuthRequest {
                userkey,
                email,
                auth_request_id,
            },
            _ => panic!("Unexpected message type"),
        }
    }
    pub async fn send_device_id(&mut self, device_id: String) {
        let encrypted_device_id = self.encryptor.encrypt(ProtocolPayload::DeviceId(device_id));
        self.websocket
            .send_message(encrypted_device_id, self.destination)
            .await
            .unwrap();
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    userkey: Vec<u8>,
    email: String,
    auth_request_id: String,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl AuthRequest {
    pub fn userkey(&self) -> Vec<u8> {
        self.userkey.clone()
    }

    pub fn email(&self) -> String {
        self.email.clone()
    }

    pub fn auth_request_id(&self) -> String {
        self.auth_request_id.clone()
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct ServerRelayInitiator {
    websocket: crate::hub_client::WebsocketHubClient,
    encryptor: crate::payload_encryptor::PayloadEncryptor,
    destination: Uuid,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl ServerRelayInitiator {
    pub async fn connect(uuid: String, psk: Vec<u8>) -> Self {
        let (client, encryptor) = initiator::init(Uuid::from_str(uuid.as_str()).unwrap(), psk)
            .await
            .unwrap();
        Self {
            websocket: client,
            encryptor,
            destination: Uuid::from_str(uuid.as_str()).unwrap(),
        }
    }

    pub async fn wait_for_device_id(&mut self) -> String {
        let message = self.websocket.receive_message().await.unwrap();
        let decrypted = self.encryptor.decrypt(message.message);
        match decrypted {
            ProtocolPayload::DeviceId(device_id) => device_id,
            _ => "".to_string(),
        }
    }

    pub async fn send_auth_request(
        &mut self,
        key: Vec<u8>,
        email: String,
        auth_request_id: String,
    ) {
        let encrypted_auth_request = self.encryptor.encrypt(ProtocolPayload::AuthRequest {
            userkey: key.try_into().unwrap(),
            email,
            auth_request_id,
        });
        self.websocket
            .send_message(encrypted_auth_request, self.destination)
            .await
            .unwrap();
    }
}
