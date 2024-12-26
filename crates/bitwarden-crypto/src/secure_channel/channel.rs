use std::sync::{Arc, Mutex};

use dhkem::{DhDecapsulator, DhEncapsulator};
use kem::{Decapsulate, Encapsulate};
use rand::Rng;
use serde::{Deserialize, Serialize};

use super::{ratcheting_key::RatchetingKey, staged_key::StagedKey};
use crate::{chacha20::XChaCha20Poly1305Blake3CTXCiphertext, x25519_kem};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum ChannelError {
    NoData,
    LockError,
    ReplayAttack,
    InvalidEncyrption,
    FormatError,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum MessageType {
    RekeyInit,
    RekeyResponse,
    Data,
}

struct SecureChannelCryptoState {
    decapsulation_key: Option<DhDecapsulator<x25519_dalek::ReusableSecret>>,
    receive_key: StagedKey<RatchetingKey>,
    send_key: StagedKey<RatchetingKey>,
    rx_counter: u64,
    tx_counter: u64,
}

struct X25519SecureChannelWrapper {
    channel: Box<dyn Channel>,
    crypto_state: SecureChannelCryptoState,
}

#[derive(Debug, Serialize, Deserialize)]
struct MessageAD {
    message_type: MessageType,

    rx_counter: u64,
    tx_counter: u64,

    send_key_fingerprint: StagedKey<[u8; 32]>,
    receive_key_fingerprint: StagedKey<[u8; 32]>,
}

impl MessageAD {
    fn new(message_type: MessageType, crypto_state: &SecureChannelCryptoState) -> Self {
        MessageAD {
            message_type,
            rx_counter: crypto_state.rx_counter,
            tx_counter: crypto_state.tx_counter,
            send_key_fingerprint: StagedKey {
                active_key: crypto_state.send_key.active_key.fingerprint(),
                staged_key: None,
            },
            receive_key_fingerprint: StagedKey {
                active_key: crypto_state.receive_key.active_key.fingerprint(),
                staged_key: None,
            },
        }
    }
}

impl SecureChannelWrapper {
    fn send_rekey_init(crypto_state: &mut SecureChannelCryptoState, channel: &mut dyn Channel) {
        let setup_packet_ad = MessageAD::new(MessageType::RekeyInit, crypto_state);
        let setup_message = crate::chacha20::encrypt_xchacha20_poly1305_blake3_ctx(
            &[0; 32],
            Vec::new().as_slice(),
            rmp_serde::to_vec(&setup_packet).unwrap().as_slice(),
        )
        .unwrap();
        self.channel
            .send(rmp_serde::to_vec(&setup_message).unwrap().as_slice());
    }

    fn handle_rekey_init(crypto_state: &mut SecureChannelCryptoState, channel: &mut dyn Channel) {}

    fn new(mut channel: Box<dyn Channel>) -> Self {
        let crypto_state = SecureChannelCryptoState {
            decapsulation_key: None,
            receive_key: StagedKey::new(RatchetingKey::new([0; 32])),
            send_key: StagedKey::new(RatchetingKey::new([0; 32])),
            rx_counter: 0,
            tx_counter: 0,
        };
        let (decapsulation_key, encapsulation_key, encapsulation_key_hash) = x25519_kem::keypair();
        crypto_state.decapsulation_key = Some(decapsulation_key);
        let setup_packet_ad = MessageAD::new(MessageType::RekeyInit, &crypto_state);
        let setup_message = crate::chacha20::encrypt_xchacha20_poly1305_blake3_ctx(
            &[0; 32],
            Vec::new().as_slice(),
            rmp_serde::to_vec(&setup_packet_ad).unwrap().as_slice(),
        )
        .unwrap();
        channel.send(rmp_serde::to_vec(&setup_message).unwrap().as_slice());

        let received_setup_message_buffer = channel.receive().unwrap();
        let received_setup_message =
            rmp_serde::from_read(received_setup_message_buffer.as_slice()).unwrap();
        let _ = crate::chacha20::decrypt_xchacha20_poly1305_blake3_ctx(
            &[0; 32],
            &received_setup_message,
        );
        let received_setup_packet: MessageAD =
            rmp_serde::from_read(received_setup_message.authenticated_data.as_slice()).unwrap();
        let crypto_state: SecureChannelCryptoState = SecureChannelCryptoState {
            peer_encapsulation_key: StagedKey {
                active_key: PeerKey {
                    key: DhEncapsulator::from(x25519_dalek::PublicKey::from(
                        received_setup_packet
                            .staged_sender_encapsulation_key
                            .unwrap(),
                    )),
                    fingerprint: received_setup_packet
                        .sender_encapuslation_fingerprint
                        .active_key,
                },
                staged_key: None,
            },
            own_encapsulation_key: StagedKey {
                active_key: PeerKey {
                    key: (decapsulation_key, encapsulation_key),
                    fingerprint: encapsulation_key_hash,
                },
                staged_key: None,
            },
            receive_key: StagedKey::new(RatchetingKey::new([0; 32])),
            send_key: StagedKey::new(RatchetingKey::new([0; 32])),
            should_send_new_key: false,
        };

        let wrapper = SecureChannelWrapper {
            channel,
            crypto_state,
            rx_counter: 0,
            tx_counter: 0,
        };

        wrapper
    }
}

// pub trait Channel {
//     fn send(&mut self, data: &[u8]);
//     fn receive(&mut self) -> Result<Vec<u8>, ChannelError>;
//     fn id(&self) -> u8;
// }

// impl Channel for SecureChannelWrapper {
//     fn id(&self) -> u8 {
//         self.channel.id()
//     }

//     fn send(&mut self, data: &[u8]) {
//         self.tx_counter += 1;

//         if self.tx_counter % 3 == 0 {
//             let (decapsulation_key, encapsulation_key, encapsulation_key_hash) =
//                 x25519_kem::keypair();
//             println!(
//                 "{} new encaps key hash {:?}",
//                 self.id(),
//                 hex::encode(encapsulation_key_hash)
//             );
//             self.crypto_state.own_encapsulation_key.stage_key(PeerKey {
//                 key: (decapsulation_key, encapsulation_key),
//                 fingerprint: encapsulation_key_hash,
//             });
//         }

//         let (
//             staged_encapsulation_key,
//             staged_encapsulation_key_fingerprint,
//             staged_send_key,
//             staged_sendkey_fingerprint,
//         ) = if self.crypto_state.own_encapsulation_key.staged_key.is_some() {
//             let staged_key = self
//                 .crypto_state
//                 .own_encapsulation_key
//                 .staged_key
//                 .as_ref()
//                 .unwrap();
//             (
//                 Some(*(staged_key.key.1.into_inner().as_bytes())),
//                 Some(staged_key.fingerprint),
//                 None,
//                 None,
//             )
//         } else {
//             if self.crypto_state.should_send_new_key {
//                 let (pk, shared_secret) = self
//                     .crypto_state
//                     .peer_encapsulation_key
//                     .active_key
//                     .key
//                     .encapsulate(&mut rand::thread_rng())
//                     .unwrap();

//                 let encrypted_new_key = crate::chacha20::encrypt_xchacha20_poly1305_blake3_ctx(
//                     &shared_secret.as_bytes(),
//                     self.crypto_state
//                         .send_key
//                         .staged_key
//                         .as_ref()
//                         .unwrap()
//                         .as_slice(),
//                     Vec::new().as_slice(),
//                 )
//                 .unwrap();
//                 let enc_msg_encoded = rmp_serde::to_vec(&encrypted_new_key).unwrap();
//                 let msg = pk
//                     .as_bytes()
//                     .to_vec()
//                     .into_iter()
//                     .chain(enc_msg_encoded.into_iter())
//                     .collect();
//                 (
//                     None,
//                     None,
//                     Some(msg),
//                     Some(
//                         self.crypto_state
//                             .send_key
//                             .staged_key
//                             .as_ref()
//                             .unwrap()
//                             .fingerprint(),
//                     ),
//                 )
//             } else {
//                 let ratchet_key = self.crypto_state.send_key.active_key.ratchet();
//                 // println!(
//                 //     "{} ratcheting send key {:?}",
//                 //     self.id(),
//                 //     hex::encode(ratchet_key.fingerprint())
//                 // );
//                 let result = (None, None, None, Some(ratchet_key.fingerprint()));
//                 self.crypto_state.send_key.stage_key(ratchet_key);
//                 result
//             }
//         };

//         let additional_data = MessageAD {
//             rx_counter: self.rx_counter,
//             tx_counter: self.tx_counter,
//             sender_encapuslation_fingerprint: StagedKey {
//                 active_key: self
//                     .crypto_state
//                     .own_encapsulation_key
//                     .active_key
//                     .fingerprint,
//                 staged_key: staged_encapsulation_key_fingerprint,
//             },
//             receiver_encapsulation_fingerprint: StagedKey {
//                 active_key: self
//                     .crypto_state
//                     .peer_encapsulation_key
//                     .active_key
//                     .fingerprint,
//                 staged_key: match self.crypto_state.peer_encapsulation_key.get_staged_key() {
//                     Some(key) => Some(key.fingerprint),
//                     None => None,
//                 },
//             },
//             send_key_fingerprint: StagedKey {
//                 active_key: self.crypto_state.send_key.active_key.fingerprint(),
//                 staged_key: staged_sendkey_fingerprint,
//             },
//             receive_key_fingerprint: StagedKey {
//                 active_key: self.crypto_state.receive_key.active_key.fingerprint(),
//                 staged_key: self
//                     .crypto_state
//                     .receive_key
//                     .staged_key
//                     .as_ref()
//                     .map(|key| key.fingerprint()),
//             },

//             staged_sender_encapsulation_key: staged_encapsulation_key.map(|key| key.into()),
//             staged_send_key,
//         };
//         let serialized_additional_data = rmp_serde::to_vec(&additional_data).unwrap();
//         let encrypted_message = crate::chacha20::encrypt_xchacha20_poly1305_blake3_ctx(
//             &self.crypto_state.send_key.active_key.inner(),
//             data,
//             serialized_additional_data.as_slice(),
//         )
//         .unwrap();
//         let enc_msg_encoded = rmp_serde::to_vec(&encrypted_message).unwrap();
//         self.channel.send(enc_msg_encoded.as_slice());
//     }

//     fn receive(&mut self) -> Result<Vec<u8>, ChannelError> {
//         let parsed_message = rmp_serde::from_read(self.channel.receive()?.as_slice())
//             .map_err(|_| ChannelError::FormatError)?;
//         let dec = crate::chacha20::decrypt_xchacha20_poly1305_blake3_ctx(
//             &self.crypto_state.receive_key.active_key.inner(),
//             &parsed_message,
//         );
//         let dec = match dec {
//             Ok(dec) => dec,
//             Err(_) => {
//                 if let Some(staged_key) = self.crypto_state.receive_key.get_staged_key() {
//                     let dec = crate::chacha20::decrypt_xchacha20_poly1305_blake3_ctx(
//                         &staged_key.inner(),
//                         &parsed_message,
//                     );
//                     match dec {
//                         Ok(dec) => {
//                             // println!(
//                             //     "{} finalizing key {:?}",
//                             //     self.id(),
//                             //     hex::encode(staged_key.fingerprint())
//                             // );
//                             self.crypto_state.receive_key.finalize_key();
//                             dec
//                         }
//                         Err(_) => return Err(ChannelError::InvalidEncyrption),
//                     }
//                 } else {
//                     return Err(ChannelError::InvalidEncyrption);
//                 }
//             }
//         };
//         let packet_metadata: MessageAD =
//             rmp_serde::from_read(parsed_message.authenticated_data.as_slice()).unwrap();

//         if packet_metadata.tx_counter <= self.rx_counter {
//             return Err(ChannelError::ReplayAttack);
//         }
//         self.rx_counter = packet_metadata.tx_counter;

//         if packet_metadata.staged_send_key.is_none() {
//             if packet_metadata.send_key_fingerprint.staged_key.is_some() {
//                 let new_receive_key = self.crypto_state.receive_key.active_key.ratchet();
//                 if new_receive_key.fingerprint()
//                     == packet_metadata.send_key_fingerprint.staged_key.unwrap()
//                 {
//                     // println!(
//                     //     "{} staging new receive key {:?}",
//                     //     self.id(),
//                     //     hex::encode(new_receive_key.fingerprint())
//                     // );
//                     self.crypto_state.receive_key.stage_key(new_receive_key);
//                 } else {
//                     println!(
//                         "{} send_key_fingerprint mismatch got {:?} expected {:?}, ratchet of
// {:?}",                         self.id(),
//                         hex::encode(packet_metadata.send_key_fingerprint.staged_key.unwrap()),
//                         hex::encode(new_receive_key.fingerprint()),
//                         hex::encode(self.crypto_state.receive_key.active_key.fingerprint())
//                     );
//                 }
//             }
//         }

//         if let Some(remote_staged_receive_key_fingerprint) =
//             packet_metadata.receive_key_fingerprint.staged_key
//         {
//             let own_staged_receive_key = self.crypto_state.send_key.staged_key.as_ref().unwrap();
//             if own_staged_receive_key.fingerprint() == remote_staged_receive_key_fingerprint {
//                 // println!(
//                 //     "{} finalized key {:?}",
//                 //     self.id(),
//                 //     hex::encode(own_staged_receive_key.fingerprint())
//                 // );
//                 self.crypto_state.send_key.finalize_key();
//                 if self.crypto_state.should_send_new_key {
//                     println!("{} updated key via transfer", self.id());
//                     self.crypto_state.should_send_new_key = false;
//                 } else {
//                     println!("{} updated key via ratchet", self.id());
//                 }
//             } else {
//                 println!(
//                     "rx key fingerprint mismatch {:?} != {:?}",
//                     hex::encode(own_staged_receive_key.fingerprint()),
//                     hex::encode(remote_staged_receive_key_fingerprint)
//                 );
//             }
//         }

//         if let Some(enc_key) = packet_metadata.staged_sender_encapsulation_key {
//             // println!(
//             //     "{} staging encaps key hash{:?}",
//             //     self.id(),
//             //     hex::encode(
//             //         packet_metadata
//             //             .sender_encapuslation_fingerprint
//             //             .staged_key
//             //             .unwrap()
//             //     )
//             // );
//             self.crypto_state.peer_encapsulation_key.stage_key(PeerKey {
//                 key: DhEncapsulator::from(x25519_dalek::PublicKey::from(enc_key)),
//                 fingerprint: packet_metadata
//                     .sender_encapuslation_fingerprint
//                     .staged_key
//                     .unwrap(),
//             });
//         }

//         if let Some(staged_key) = self.crypto_state.own_encapsulation_key.staged_key.as_ref() {
//             if let Some(remote_staged_key) = packet_metadata
//                 .receiver_encapsulation_fingerprint
//                 .staged_key
//             {
//                 if staged_key.fingerprint == remote_staged_key {
//                     // println!(
//                     //     "{:?} finalizing own key, is now {:?}",
//                     //     self.id(),
//                     //     hex::encode(staged_key.fingerprint)
//                     // );
//                     self.crypto_state.own_encapsulation_key.finalize_key();
//                     // println!(
//                     //     "{:?} after finalize {:?}",
//                     //     self.id(),
//                     //     hex::encode(
//                     //         self.crypto_state
//                     //             .own_encapsulation_key
//                     //             .active_key
//                     //             .fingerprint
//                     //     )
//                     // );
//                 } else {
//                     println!("{:?} staged key fingerprint mismatch", self.id());
//                 }
//             } else {
//                 println!("{:?} staged key but no remote key", self.id());
//             }
//         }

//         if let Some(staged_key) = self.crypto_state.peer_encapsulation_key.staged_key.as_ref() {
//             // println!(
//             //     "{:?} staged key {:?} vs {:?}",
//             //     self.id(),
//             //     hex::encode(staged_key.fingerprint),
//             //     hex::encode(packet_metadata.sender_encapuslation_fingerprint.active_key),
//             // );
//             if staged_key.fingerprint ==
// packet_metadata.sender_encapuslation_fingerprint.active_key             {
//                 // println!("{:?} finalizing peer key", self.id());
//                 self.crypto_state.peer_encapsulation_key.finalize_key();
//                 self.crypto_state.should_send_new_key = true;
//                 let new_key: [u8; 32] = rand::thread_rng().gen();
//                 let new_key = RatchetingKey::new(new_key);
//                 // println!(
//                 //     "{:?} staging session key {:?}",
//                 //     self.id(),
//                 //     hex::encode(new_key.fingerprint())
//                 // );
//                 self.crypto_state.send_key.stage_key(new_key);
//             }
//         }

//         if let Some(tx_key) = packet_metadata.staged_send_key {
//             // first 32 bytes are the key
//             let (encapsulated_key, encrypted_key) = tx_key.split_at(32);
//             let tx_key: [u8; 32] = encapsulated_key.try_into().unwrap();
//             let encapsulated_key = x25519_dalek::PublicKey::from(tx_key);
//             let shared_secret = self
//                 .crypto_state
//                 .own_encapsulation_key
//                 .active_key
//                 .key
//                 .0
//                 .decapsulate(&encapsulated_key)
//                 .unwrap();
//             let ciphertext: XChaCha20Poly1305Blake3CTXCiphertext =
//                 rmp_serde::from_slice(encrypted_key).unwrap();
//             let decrypted_key = crate::chacha20::decrypt_xchacha20_poly1305_blake3_ctx(
//                 &shared_secret.as_bytes(),
//                 &ciphertext,
//             );
//             let decrypted_key = decrypted_key.unwrap();
//             let new_ratcheting_key =
//                 RatchetingKey::new(decrypted_key.as_slice().try_into().unwrap());
//             self.crypto_state.receive_key.stage_key(new_ratcheting_key);
//         }

//         Ok(dec)
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;

    pub enum MockChannelError {
        EmptyBuffer,
        LockError,
    }

    struct MockChannel {
        pub buffer: Arc<Mutex<Vec<Vec<u8>>>>,
        pub other_channel: Arc<Mutex<Vec<Vec<u8>>>>,
        pub id: u8,
    }

    impl MockChannel {
        fn new_pair() -> (Self, Self) {
            let buffer1 = Arc::new(Mutex::new(Vec::new()));
            let buffer2 = Arc::new(Mutex::new(Vec::new()));
            let channel1 = MockChannel {
                buffer: buffer1.clone(),
                other_channel: buffer2.clone(),
                id: 1,
            };
            let channel2 = MockChannel {
                buffer: buffer2.clone(),
                other_channel: buffer1.clone(),
                id: 2,
            };
            (channel1, channel2)
        }
    }

    impl Channel for MockChannel {
        fn id(&self) -> u8 {
            self.id
        }

        fn send(&mut self, data: &[u8]) {
            self.other_channel.lock().unwrap().insert(0, data.to_vec());
        }

        fn receive(&mut self) -> Result<Vec<u8>, ChannelError> {
            loop {
                if self.buffer.lock().unwrap().len() == 0 {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                } else {
                    break;
                }
            }
            Ok(self
                .buffer
                .lock()
                .map_err(|_| ChannelError::LockError)?
                .pop()
                .ok_or(ChannelError::NoData)?)
        }
    }

    #[test]
    fn test_secure_channel() {
        let (channel1, channel2) = MockChannel::new_pair();

        // start two threads
        let thread = std::thread::spawn(move || {
            let mut secure_channel1 = SecureChannelWrapper::new(Box::new(channel1));
            for i in 0..500 {
                secure_channel1.send(format!("Hello, world! {}", i).as_bytes());
                //println!("sent 1 {}", i);
                let res = secure_channel1.receive().unwrap();
                assert_eq!(res, format!("Hello, world! {}", i).as_bytes());
            }
        });
        let thread2 = std::thread::spawn(move || {
            let mut secure_channel2 = SecureChannelWrapper::new(Box::new(channel2));
            for i in 0..500 {
                let res = secure_channel2.receive().unwrap();
                assert_eq!(res, format!("Hello, world! {}", i).as_bytes());
                secure_channel2.send(format!("Hello, world! {}", i).as_bytes());
                //println!("sent 2 {}", i);
            }
        });

        thread.join().unwrap();
        thread2.join().unwrap();
    }
}
