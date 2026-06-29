//! The IPC control plane: reserved topics for transport-level frames that travel over the raw
//! transport and deliberately bypass the crypto channel (reachability ping/pong).
//!
//! Frames whose topic falls under [`CONTROL_TOPIC_PREFIX`] are peeled off by the
//! [`ControlSplitter`](crate::control_splitter::ControlSplitter) before the crypto layer ever sees
//! them, so they can measure liveness without (and without disturbing) a crypto session.

use crate::{
    endpoint::{Endpoint, Source},
    message::OutgoingMessage,
};

/// Reserved topic namespace for transport control frames that bypass the crypto channel.
pub(crate) const CONTROL_TOPIC_PREFIX: &str = "$bw.control.";
/// Topic marking a plaintext reachability ping.
pub(crate) const CONTROL_PING_TOPIC: &str = "$bw.control.ping";
/// Topic marking a plaintext reachability pong (the reply to a ping).
pub(crate) const CONTROL_PONG_TOPIC: &str = "$bw.control.pong";

/// Whether `topic` belongs to the reserved control-topic namespace and must bypass crypto.
pub(crate) fn is_control_topic(topic: Option<&str>) -> bool {
    topic.is_some_and(|t| t.starts_with(CONTROL_TOPIC_PREFIX))
}

/// A transport control-plane message. These ride the reserved control topics over the raw
/// transport rather than the crypto channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControlMessage {
    /// Liveness probe.
    Ping,
    /// Reply to a [`ControlMessage::Ping`].
    Pong,
}

impl ControlMessage {
    /// The reserved topic this message rides on.
    pub(crate) fn topic(self) -> &'static str {
        match self {
            ControlMessage::Ping => CONTROL_PING_TOPIC,
            ControlMessage::Pong => CONTROL_PONG_TOPIC,
        }
    }

    /// Parse a control message from a frame's topic, returning `None` for non-control frames.
    pub(crate) fn from_topic(topic: Option<&str>) -> Option<Self> {
        match topic {
            Some(CONTROL_PING_TOPIC) => Some(ControlMessage::Ping),
            Some(CONTROL_PONG_TOPIC) => Some(ControlMessage::Pong),
            _ => None,
        }
    }

    /// Build the outgoing frame carrying this control message to `destination`.
    pub(crate) fn to_outgoing(self, destination: Endpoint) -> OutgoingMessage {
        OutgoingMessage {
            payload: Vec::new(),
            destination,
            topic: Some(self.topic().to_owned()),
        }
    }
}

/// An inbound [`ControlMessage`] together with the peer it came from.
pub(crate) struct IncomingControlMessage {
    pub(crate) message: ControlMessage,
    pub(crate) source: Source,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_control_topic_matches_namespace() {
        assert!(is_control_topic(Some(CONTROL_PING_TOPIC)));
        assert!(is_control_topic(Some(CONTROL_PONG_TOPIC)));
        assert!(is_control_topic(Some("$bw.control.future")));
        assert!(!is_control_topic(Some("some-rpc-topic")));
        assert!(!is_control_topic(None));
    }
}
