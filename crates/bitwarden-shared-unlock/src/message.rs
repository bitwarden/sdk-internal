use bitwarden_core::UserId;
use bitwarden_ipc::PayloadTypeName;
use serde::{Deserialize, Serialize};

use crate::LockState;

/// The messages sent from followers to the leader
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum FollowerMessage {
    /// Synchronizes a user's lock state between participants.
    LockStateUpdate {
        /// User whose lock state is being synchronized.
        user_id: UserId,
        /// New lock state for the user.
        lock_state: LockState,
    },
    /// A follower, upon startup should send the `StartSession` message to the leader to
    /// announce its presence. It also sends the lock state. The leader then should unlock
    /// if it is locked and the follower sent an unlocked state, otherwise it should not change
    /// the lock state. Subsequently, it should respond with a lockstate update.
    StartSession {
        /// User whose session is starting.
        user_id: UserId,
        /// Current lock state for the user.
        lock_state: LockState,
    },
    /// A heartbeat request to the leader every `HEARTBEAT_INTERVAL`.
    HeartBeat {
        /// User whose session liveness is being reported.
        user_id: UserId,
    },
}

/// The messages sent from the leader to followers
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum LeaderMessage {
    /// Synchronizes a user's lock state between participants.
    LockStateUpdate {
        /// User whose lock state is being synchronized.
        user_id: UserId,
        /// New lock state for the user.
        lock_state: LockState,
    },
    /// The leader response to the follower's heartbeat request.
    HeartBeat {
        /// User whose session liveness is being reported.
        user_id: UserId,
    },
}

impl FollowerMessage {
    /// Returns the user ID associated with the message.
    pub fn user_id(&self) -> UserId {
        match self {
            FollowerMessage::LockStateUpdate { user_id, .. }
            | FollowerMessage::StartSession { user_id, .. }
            | FollowerMessage::HeartBeat { user_id } => *user_id,
        }
    }
}

impl PayloadTypeName for FollowerMessage {
    const PAYLOAD_TYPE_NAME: &'static str = "password-manager.shared-unlock.follower-to-leader";
}

impl LeaderMessage {
    /// Returns the user ID associated with the message.
    pub fn user_id(&self) -> UserId {
        match self {
            LeaderMessage::LockStateUpdate { user_id, .. }
            | LeaderMessage::HeartBeat { user_id } => *user_id,
        }
    }
}

impl PayloadTypeName for LeaderMessage {
    const PAYLOAD_TYPE_NAME: &'static str = "password-manager.shared-unlock.leader-to-follower";
}
