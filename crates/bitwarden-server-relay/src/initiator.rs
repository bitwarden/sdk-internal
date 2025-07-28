use snow::params::NoiseParams;
use std::sync::LazyLock;
use uuid::Uuid;

use crate::hub_client::{self, HubClient};

use crate::payload_encryptor::PayloadEncryptor;

pub(crate) async fn init(
    destination_uuid: Uuid,
    psk: Vec<u8>,
) -> Result<(hub_client::WebsocketHubClient, PayloadEncryptor), ()> {
    let mut client = hub_client::WebsocketHubClient::new().await;
    client.connect().await.unwrap();
    let encryptor = handshake(&mut client, destination_uuid, psk).await.unwrap();
    Ok((client, encryptor))
}

async fn handshake(
    client: &mut hub_client::WebsocketHubClient,
    destination_uuid: Uuid,
    psk: Vec<u8>,
) -> Result<PayloadEncryptor, ()> {
    let builder = snow::Builder::new("Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
    println!("builder");
    let static_key = builder.generate_keypair().unwrap().private;
    println!("static");
    let mut noise = builder
        .local_private_key(static_key.as_slice())
        .psk(3, psk.as_slice())
        .build_initiator()
        .unwrap();
    println!("abc");

    // The PSK3 pattern needs write-read-write on initiator to establish all security properties

    let mut buf = [0u8; 65535];
    let len = noise.write_message(&[], &mut buf).map_err(|_| ())?;
    println!("noise");
    client
        .send_message(buf[..len].to_vec(), destination_uuid)
        .await
        .unwrap();

    println!("A Handshake sent");

    let response = client.receive_message().await.unwrap();
    println!("Received response: {:?}", response);
    let mut buf = Vec::new();
    noise.read_message(&response.message, &mut buf).unwrap();
    println!("Received noise message: {:?}", buf);

    let mut buf = [0u8; 65535];
    let len = noise.write_message(&[], &mut buf).map_err(|_| ())?;
    client
        .send_message(buf[..len].to_vec(), destination_uuid)
        .await
        .map_err(|_| ())?;

    let transport_mode = noise.into_transport_mode().unwrap();
    println!("transport mode: {:?}", transport_mode);
    Ok(PayloadEncryptor::new(transport_mode))
}

#[cfg(test)]
mod test {
    use uuid::Uuid;

    use crate::initiator::init;

    #[tokio::test]
    async fn test_initiator_handshake() {
        let destination_uuid = Uuid::new_v4();
        let (client, encryptor) = init(destination_uuid, vec![0u8; 32]).await.unwrap();
    }
}
