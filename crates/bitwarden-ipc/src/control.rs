//! The IPC control plane: reserved topics for transport-level frames that travel over the raw
//! transport and deliberately bypass the crypto channel (reachability ping/pong).
//!
//! Frames whose topic falls under [`CONTROL_TOPIC_PREFIX`] are peeled off by the
//! [`ControlSplitter`](crate::control_splitter::ControlSplitter) before the crypto layer ever sees
//! them, so they can measure liveness without (and without disturbing) a crypto session.

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
