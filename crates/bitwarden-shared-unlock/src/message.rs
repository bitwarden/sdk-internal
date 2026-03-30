use bitwarden_core::UserId;
use bitwarden_crypto::EncodingError;
use serde::{Deserialize, Serialize};

use crate::LockState;

/// The messages sent between the followers and leader
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Message {
    /// Follower -> Leader, Leader -> Follower
    ///
    /// Synchronizes a user's lock state between participants.
    LockStateUpdate {
        /// User whose lock state is being synchronized.
        user_id: UserId,
        /// New lock state for the user.
        lock_state: LockState,
    },
    /// Follower -> Leader
    ///
    /// A follower, upon startup should send the `StartSession` message to the leader to
    /// announce its presence. It also sends the lock state. The leader then should unlock
    /// if it is locked and the follower sent an unlocked state, otherwise it should not change
    /// the lock state. Subsequently, it should respond with a lockstate update.
    StartSession {
        /// User whose session is starting.
        user_id: UserId,
        /// Follower's current local lock state.
        lock_state: LockState,
    },
    /// Follower -> Leader, Leader -> Follower
    ///
    /// The follower sends a heartbeat request to the leader every `HEARTBEAT_INTERVAL`.
    /// The leader responds with a HeartBeat.
    HeartBeat {
        /// User whose session liveness is being reported.
        user_id: UserId,
    },
}

impl Message {
    /// Returns the user ID associated with this message.
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
