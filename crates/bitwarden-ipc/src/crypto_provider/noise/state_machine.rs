use serde::{Deserialize, Serialize};
use tracing::info;

use crate::crypto_provider::noise::{
    handshake::{HandshakeInitiator, HandshakeResponder},
    transport_state::{
        Message, Payload, PersistentTransportState, TransportFrame, current_epoch_secs,
    },
};

/// Serializable representation of the noise state machine.
///
/// In-flight handshake initiator state (`HandshakeStart`) is not serializable and is
/// collapsed to the current transport state. All other variants are preserved faithfully.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) enum SerializableNoiseState {
    /// No completed handshake yet (or in-flight handshake whose initiator state was dropped).
    Initial {
        transport_state: PersistentTransportState,
    },
    /// Handshake finished but not yet confirmed by a payload exchange.
    HandshakeFinish {
        transport_state: PersistentTransportState,
        staged_transport_state: PersistentTransportState,
    },
    /// Established session with a confirmed transport state.
    Transport {
        transport_state: PersistentTransportState,
    },
}

/// This represents the states the noise protocol can be in. In the bitwarden-ipc variant
/// of the noise protocol, we start with an initial (insecure) transport state, which gets
/// transitioned to a new transport state via a handshake.
#[allow(clippy::large_enum_variant)]
pub(crate) enum NoiseStateMachine {
    // Can transition to: HandshakeStart when initiating a Handshake, HandshakeFinish when
    // responding to a Handshake
    Initial {
        transport_state: PersistentTransportState,
    },
    // Can transition to: HandshakeFinish
    HandshakeStart {
        transport_state: PersistentTransportState,
        handshake_state: HandshakeInitiator,
    },
    // Can transition to: Transport
    HandshakeFinish {
        transport_state: PersistentTransportState,
        staged_transport_state: PersistentTransportState,
    },
    // Can transition to: HandshakeStart when initiating a handshake, HandshakeFinish when
    // responding to a handshake
    Transport {
        transport_state: PersistentTransportState,
    },
}

impl NoiseStateMachine {
    pub(crate) fn new_initial() -> Self {
        Self::Initial {
            transport_state: PersistentTransportState::null(),
        }
    }

    /// Returns whether the state machine needs a handshake before it can send payload messages.
    pub(crate) fn needs_handshake(&self) -> bool {
        matches!(self, Self::Initial { .. })
    }

    /// Returns whether the current transport session is older than `max_age_secs` and should
    /// be re-keyed. Only returns `true` when in the `Transport` state with a known handshake
    /// timestamp that exceeds the threshold.
    pub(crate) fn needs_rehandshake(&self, max_age_secs: u64) -> bool {
        match self {
            Self::Transport { transport_state } => {
                let last_handshake = transport_state.last_handshake_epoch_secs();
                let now = current_epoch_secs();
                now.saturating_sub(last_handshake) >= max_age_secs
            }
            _ => false,
        }
    }

    /// Converts the state machine into a serializable representation.
    ///
    /// The `HandshakeStart` variant loses its in-flight `HandshakeInitiator` and is
    /// collapsed to `Initial`; the handshake will be re-initiated on the next send.
    pub(crate) fn to_serializable(&self) -> SerializableNoiseState {
        match self {
            Self::Initial { transport_state }
            | Self::HandshakeStart {
                transport_state, ..
            } => SerializableNoiseState::Initial {
                transport_state: transport_state.clone(),
            },
            Self::HandshakeFinish {
                transport_state,
                staged_transport_state,
            } => SerializableNoiseState::HandshakeFinish {
                transport_state: transport_state.clone(),
                staged_transport_state: staged_transport_state.clone(),
            },
            Self::Transport { transport_state } => SerializableNoiseState::Transport {
                transport_state: transport_state.clone(),
            },
        }
    }

    /// Reconstructs a state machine from a serialized representation.
    pub(crate) fn from_serializable(state: SerializableNoiseState) -> Self {
        match state {
            SerializableNoiseState::Initial { transport_state } => {
                Self::Initial { transport_state }
            }
            SerializableNoiseState::HandshakeFinish {
                transport_state,
                staged_transport_state,
            } => Self::HandshakeFinish {
                transport_state,
                staged_transport_state,
            },
            SerializableNoiseState::Transport { transport_state } => {
                Self::Transport { transport_state }
            }
        }
    }

    pub(crate) fn start_handshake(&mut self) -> Result<TransportFrame, ()> {
        match self {
            Self::Initial { transport_state } | Self::Transport { transport_state } => {
                let mut initiator = HandshakeInitiator::new(&Default::default())?;
                let handshake_start_message = initiator.write_start_message()?;
                let transport_frame = transport_state.send(handshake_start_message.into())?;
                *self = Self::HandshakeStart {
                    transport_state: transport_state.clone(),
                    handshake_state: initiator,
                };
                Ok(transport_frame)
            }
            _ => Err(()),
        }
    }

    pub(crate) fn send(&mut self, payload: Payload) -> Result<TransportFrame, ()> {
        match self {
            Self::Transport { transport_state } => {
                transport_state.send(Message::Payload { payload })
            }
            // If we have finished the handshake, always send with the new key. The other side will
            // then commit the staged transport state once receiving with the new key.
            Self::HandshakeFinish {
                staged_transport_state,
                ..
            } => staged_transport_state.send(Message::Payload { payload }),
            _ => Err(()),
        }
    }

    pub(crate) fn receive(&mut self, transport_frame: TransportFrame) -> Result<ReceiveResult, ()> {
        match self {
            NoiseStateMachine::Initial { transport_state } => {
                let message = transport_state.receive(&transport_frame).map_err(|_| ())?;

                // Guard against invalid messages. Only Initial -> HandshakeStart is a valid
                // transition
                let Message::HandshakeStart { handshake_start } = message else {
                    return Err(());
                };

                let mut responder = HandshakeResponder::new(&handshake_start.ciphersuite)?;
                responder.read_start_message(&handshake_start)?;
                let response_message = responder.write_response_message()?;
                let response_frame = transport_state.send(response_message.into())?;
                let staged_transport_state = (&mut responder).into();
                info!("Handshake complete; staging new keys");
                *self = NoiseStateMachine::HandshakeFinish {
                    transport_state: transport_state.clone(),
                    staged_transport_state,
                };
                Ok(ReceiveResult::NeedsMessageSent {
                    message: response_frame,
                })
            }
            NoiseStateMachine::HandshakeStart {
                transport_state,
                handshake_state,
            } => {
                let message = transport_state.receive(&transport_frame).map_err(|_| ())?;

                // Guard against invalid messages. Only HandshakeStart -> HandshakeFinish is a valid
                // transition
                let Message::HandshakeFinish { handshake_finish } = message else {
                    return Err(());
                };

                handshake_state.read_response_message(&handshake_finish)?;
                let staged_transport_state = handshake_state.into();
                info!("Handshake complete; staging new keys");
                *self = NoiseStateMachine::HandshakeFinish {
                    transport_state: transport_state.clone(),
                    staged_transport_state,
                };

                Ok(ReceiveResult::Nothing)
            }
            // HandshakeFinish -Payload-> Transport when we receive a payload (confirms peer adopted
            // new keys) HandshakeFinish -Payload-> HandshakeFinish when we receive a
            // handshake start (new re-key while finishing)
            NoiseStateMachine::HandshakeFinish {
                transport_state,
                staged_transport_state,
            } => {
                if let Ok(message) = staged_transport_state.receive(&transport_frame) {
                    info!("Switching to new transport state");
                    *self = NoiseStateMachine::Transport {
                        transport_state: staged_transport_state.clone(),
                    };

                    return match message {
                        Message::Payload { payload } => {
                            Ok(ReceiveResult::ReceivedMessage { payload })
                        }
                        _ => Err(()),
                    };
                }

                if let Ok(message) = transport_state.receive(&transport_frame) {
                    match message {
                        Message::Payload { payload } => {
                            return Ok(ReceiveResult::ReceivedMessage { payload });
                        }
                        _ => return Err(()),
                    }
                }

                Err(())
            }
            // Transport -Payload-> Transport when we receive a payload
            // Transport -HandshakeStart-> HandshakeFinish when we receive a handshake start
            // (re-key)
            NoiseStateMachine::Transport { transport_state } => {
                if let Ok(message) = transport_state.receive(&transport_frame) {
                    match message {
                        Message::Payload { payload } => {
                            return Ok(ReceiveResult::ReceivedMessage { payload });
                        }
                        Message::HandshakeStart { handshake_start } => {
                            let mut responder =
                                HandshakeResponder::new(&handshake_start.ciphersuite)?;
                            responder.read_start_message(&handshake_start)?;
                            let response_message = responder.write_response_message()?;
                            let response_frame = transport_state.send(response_message.into())?;
                            let staged_transport_state = (&mut responder).into();
                            *self = NoiseStateMachine::HandshakeFinish {
                                transport_state: transport_state.clone(),
                                staged_transport_state,
                            };
                            return Ok(ReceiveResult::NeedsMessageSent {
                                message: response_frame,
                            });
                        }
                        _ => return Err(()),
                    }
                }

                // If we fail to read with the current keys, we might be in the middle of a re-key
                // and need to try reading with the old keys as well.
                Err(())
            }
        }
    }
}

// This represents the the result of a recieve operation. This can either require sending a message,
// or have successfully received a message.
#[derive(Debug)]
pub(crate) enum ReceiveResult {
    NeedsMessageSent { message: TransportFrame },
    ReceivedMessage { payload: Payload },
    Nothing,
}

#[cfg(test)]
mod tests {
    use crate::crypto_provider::noise::{
        state_machine::{NoiseStateMachine, ReceiveResult},
        transport_state::{
            Payload, PersistentTransportState, assert_matching_pair, assert_non_null,
        },
    };

    #[test]
    fn test_handshake() {
        let mut state1 = NoiseStateMachine::new_initial();
        let mut state2 = NoiseStateMachine::new_initial();

        // State1 initiates handshake
        let handshake_message = state1.start_handshake().expect("Handshake should start");
        // State2 receives handshake message and responds
        let receive_result = state2
            .receive(handshake_message)
            .expect("State2 should receive handshake message");
        let response_message = match receive_result {
            ReceiveResult::NeedsMessageSent { message } => message,
            _ => panic!("State2 should need to send a response message"),
        };
        // State1 receives response message and finishes handshake
        let receive_result = state1
            .receive(response_message)
            .expect("State1 should receive handshake response message");
        match receive_result {
            ReceiveResult::Nothing => {}
            _ => panic!("State1 should not need to send a message or have received a payload"),
        };

        // send to each other to confirm transport state is active
        let payload1: Payload = b"Hello from state1".to_vec().into();
        let payload2: Payload = b"Hello from state2".to_vec().into();
        let message1 = state1
            .send(payload1.clone())
            .expect("State1 should send message");
        let message2 = state2
            .send(payload2.clone())
            .expect("State2 should send message");
        let receive_result = state1
            .receive(message2)
            .expect("State1 should receive message from state2");
        match receive_result {
            ReceiveResult::ReceivedMessage { payload } => {
                assert_eq!(payload, payload2);
            }
            _ => panic!("State1 should have received a message"),
        };
        let receive_result = state2
            .receive(message1)
            .expect("State2 should receive message from state1");
        match receive_result {
            ReceiveResult::ReceivedMessage { payload } => {
                assert_eq!(payload, payload1);
            }
            _ => panic!("State2 should have received a message"),
        }

        match (&state1, &state2) {
            (
                NoiseStateMachine::Transport {
                    transport_state: ts1,
                },
                NoiseStateMachine::Transport {
                    transport_state: ts2,
                },
            ) => {
                assert_matching_pair(ts1, ts2);
                assert_non_null(ts1);
                assert_non_null(ts2);
            }
            _ => panic!("Both states should be in Transport state"),
        }
    }

    #[test]
    fn needs_rehandshake_false_for_initial_state() {
        let state = NoiseStateMachine::new_initial();
        assert!(!state.needs_rehandshake(0));
    }

    #[test]
    fn needs_rehandshake_false_for_fresh_transport() {
        let mut state1 = NoiseStateMachine::new_initial();
        let mut state2 = NoiseStateMachine::new_initial();

        // Complete a handshake to reach Transport state
        let hs = state1.start_handshake().expect("start handshake");
        let resp = match state2.receive(hs).expect("receive") {
            ReceiveResult::NeedsMessageSent { message } => message,
            _ => panic!("expected NeedsMessageSent"),
        };
        let _ = state1.receive(resp).expect("receive response");

        // Exchange one payload message so both sides move to Transport
        let frame = state1.send(b"ping".to_vec().into()).expect("send");
        let _ = state2.receive(frame).expect("receive payload");

        // With a very large max_age, the session should not be considered stale
        assert!(!state1.needs_rehandshake(u64::MAX));
        assert!(!state2.needs_rehandshake(u64::MAX));
    }

    /// Helper: perform a full handshake between two state machines and exchange one
    /// payload in each direction so both sides land in the `Transport` state.
    /// Returns the transport-state keys (send_key of state1) for later comparison.
    fn do_handshake_and_confirm(state1: &mut NoiseStateMachine, state2: &mut NoiseStateMachine) {
        // state1 initiates
        let hs = state1.start_handshake().expect("start handshake");
        let resp = match state2.receive(hs).expect("receive handshake") {
            ReceiveResult::NeedsMessageSent { message } => message,
            other => panic!("expected NeedsMessageSent, got {other:?}"),
        };
        match state1.receive(resp).expect("receive response") {
            ReceiveResult::Nothing => {}
            other => panic!("expected Nothing, got {other:?}"),
        }

        // Exchange payload messages so both sides move to Transport
        let frame1 = state1
            .send(b"hello".to_vec().into())
            .expect("state1 should send");
        let frame2 = state2
            .send(b"world".to_vec().into())
            .expect("state2 should send");
        match state2.receive(frame1).expect("state2 receives") {
            ReceiveResult::ReceivedMessage { payload } => {
                assert_eq!(payload.as_ref(), b"hello");
            }
            other => panic!("expected ReceivedMessage, got {other:?}"),
        }
        match state1.receive(frame2).expect("state1 receives") {
            ReceiveResult::ReceivedMessage { payload } => {
                assert_eq!(payload.as_ref(), b"world");
            }
            other => panic!("expected ReceivedMessage, got {other:?}"),
        }
    }

    fn extract_transport_state(sm: &NoiseStateMachine) -> &PersistentTransportState {
        match sm {
            NoiseStateMachine::Transport { transport_state } => transport_state,
            _ => panic!("expected Transport state"),
        }
    }

    #[test]
    fn test_rekey() {
        let mut state1 = NoiseStateMachine::new_initial();
        let mut state2 = NoiseStateMachine::new_initial();

        // Initial handshake
        do_handshake_and_confirm(&mut state1, &mut state2);

        // Capture a frame encrypted with the old keys
        let old_frame = state1
            .send(b"before-rekey".to_vec().into())
            .expect("send before rekey");
        // Consume it so nonces stay in sync
        match state2.receive(old_frame.clone()).expect("receive") {
            ReceiveResult::ReceivedMessage { payload } => {
                assert_eq!(payload.as_ref(), b"before-rekey");
            }
            other => panic!("expected ReceivedMessage, got {other:?}"),
        }

        // Perform re-key (state1 initiates a new handshake while in Transport)
        do_handshake_and_confirm(&mut state1, &mut state2);

        // Both sides should be in Transport with matching, non-null keys
        let ts1 = extract_transport_state(&state1);
        let ts2 = extract_transport_state(&state2);
        assert_matching_pair(ts1, ts2);
        assert_non_null(ts1);
        assert_non_null(ts2);

        // Old frame encrypted with previous keys should fail to decrypt
        assert!(
            state2.receive(old_frame).is_err(),
            "frame encrypted with old keys should not decrypt after re-key"
        );

        // Confirm communication still works after re-key
        let payload_a: Payload = b"post-rekey from state1".to_vec().into();
        let payload_b: Payload = b"post-rekey from state2".to_vec().into();
        let frame_a = state1.send(payload_a.clone()).expect("send after rekey");
        let frame_b = state2.send(payload_b.clone()).expect("send after rekey");
        match state2.receive(frame_a).expect("receive after rekey") {
            ReceiveResult::ReceivedMessage { payload } => assert_eq!(payload, payload_a),
            other => panic!("expected ReceivedMessage, got {other:?}"),
        }
        match state1.receive(frame_b).expect("receive after rekey") {
            ReceiveResult::ReceivedMessage { payload } => assert_eq!(payload, payload_b),
            other => panic!("expected ReceivedMessage, got {other:?}"),
        }
    }
}
