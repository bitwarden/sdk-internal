use bitwarden_core::UserId;
use bitwarden_crypto::EncodingError;
use serde::{Deserialize, Serialize};

use crate::LockState;

/// The messages sent between the followers and leader
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Message {
    LockStateUpdate {
        user_id: UserId,
        lock_state: LockState,
    },
    /// Follower -> Leader
    ///
    /// A follower, upon startup should send the `StartSession` message to the leader to
    /// announce its presence. It also sends the lock state. The leader then should unlock
    /// if it is locked and the follower sent an unlocked state, otherwise it should not change
    /// the lock state. Subsequently, it should respond with a lockstate update.
    StartSession {
        user_id: UserId,
        lock_state: LockState,
    },
    /// Follower -> Leader, Leader -> Follower
    ///
    /// The follower sends a heartbeat request to the leader every `HEARTBEAT_INTERVAL`.
    /// The leader responds with a HeartBeat.
    HeartBeat { user_id: UserId },
}

impl Message {
    pub fn user_id(&self) -> UserId {
        match self {
            Message::LockStateUpdate { user_id, .. }
            | Message::StartSession { user_id, .. }
            | Message::HeartBeat { user_id } => *user_id,
        }
    }

    /// Serializes this message to CBOR bytes.
    pub fn to_cbor(&self) -> Result<Vec<u8>, EncodingError> {
        let mut buffer = Vec::new();
        ciborium::ser::into_writer(self, &mut buffer)
            .map_err(|_| EncodingError::InvalidCborSerialization)?;
        Ok(buffer)
    }

    /// Deserializes a message from CBOR bytes.
    pub fn from_cbor(data: &[u8]) -> Result<Self, EncodingError> {
        ciborium::de::from_reader(data).map_err(|_| EncodingError::InvalidCborSerialization)
    }
}
