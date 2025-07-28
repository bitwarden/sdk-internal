use uuid::Uuid;

use crate::hub_client::{self, HubClient};

use crate::payload_encryptor::PayloadEncryptor;

pub async fn listen() -> Result<hub_client::WebsocketHubClient, ()> {
    let mut client = hub_client::WebsocketHubClient::new().await;
    client.connect().await.unwrap();
    Ok(client)
}

pub async fn handshake(
    client: &mut hub_client::WebsocketHubClient,
    psk: Vec<u8>,
) -> Result<(PayloadEncryptor, Uuid), ()> {
    let builder = snow::Builder::new("Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
    let static_key = builder.generate_keypair().unwrap().private;
    let mut noise = builder
        .local_private_key(static_key.as_slice())
        .psk(3, psk.as_slice())
        .build_responder()
        .unwrap();

    // The PSK3 pattern needs read-write-read on responder to establish all security properties

    let handshake_msg = client.receive_message().await.unwrap();
    let peer_id = handshake_msg.sender;
    let mut buf = Vec::new();
    noise
        .read_message(&handshake_msg.message, &mut buf)
        .unwrap();

    let mut response_buf = [0u8; 65535];
    let len = noise
        .write_message(&[], &mut response_buf)
        .map_err(|_| ())?;
    client
        .send_message(response_buf[..len].to_vec(), peer_id)
        .await
        .map_err(|_| ())?;

    let handshake_msg = client.receive_message().await.unwrap();
    let peer_id = handshake_msg.sender;
    let mut buf = Vec::new();
    noise
        .read_message(&handshake_msg.message, &mut buf)
        .unwrap();

    let transport_mode = noise.into_transport_mode().unwrap();
    Ok((PayloadEncryptor::new(transport_mode), peer_id))
}
