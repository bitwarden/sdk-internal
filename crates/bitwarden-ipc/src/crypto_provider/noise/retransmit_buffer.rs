//! Sender-side buffering of recently sent plaintexts so that messages dropped by a peer that
//! lost its session state (see
//! [`Frame::CryptoInvalidated`](super::crypto_provider::Frame::CryptoInvalidated)) can be
//! retransmitted under a freshly established session instead of being silently lost.

use std::collections::{HashMap, VecDeque};

use tracing::warn;
use zeroize::Zeroizing;

use crate::{crypto_provider::noise::transport_state::SessionId, endpoint::Endpoint};

/// Maximum number of buffered sends retained per endpoint.
const MAX_BUFFERED_SENDS_PER_ENDPOINT: usize = 16;

/// Maximum number of times a single message is retransmitted
const MAX_RETRANSMISSIONS: u8 = 2;

/// A plaintext message retained for potential retransmission.
pub(super) struct BufferedSend {
    /// The plaintext payload. May contain sensitive data (e.g. user keys)
    pub(super) payload: Zeroizing<Vec<u8>>,
    pub(super) topic: Option<String>,
    /// The session the message was (last) sent under.
    pub(super) session_id: SessionId,
    /// The message's delivery identity; stable across retransmissions.
    pub(super) message_id: u64,
    /// How many times this message has already been retransmitted.
    pub(super) retransmissions: u8,
}

/// Per-endpoint retransmit state: the increment-only message-id counters and the buffered
/// recently sent messages.
///
/// Counters and buffer are in-memory only and reset together with the process. That is sound:
/// after a restart the buffer is empty, so no stale entry can be matched against a
/// freshly started counter.
#[derive(Default)]
pub(super) struct RetransmitBuffer {
    entries: HashMap<Endpoint, VecDeque<BufferedSend>>,
    next_message_id: HashMap<Endpoint, u64>,
}

impl RetransmitBuffer {
    /// Returns the next message id for `endpoint` and advances the counter
    pub(super) fn next_message_id(&mut self, endpoint: &Endpoint) -> u64 {
        let counter = self.next_message_id.entry(endpoint.clone()).or_insert(1);
        let id = *counter;
        *counter += 1;
        id
    }

    /// Buffers a sent message for potential retransmission, evicting the oldest entry if the
    /// per-endpoint cap is exceeded.
    pub(super) fn record(&mut self, endpoint: Endpoint, entry: BufferedSend) {
        let queue = self.entries.entry(endpoint.clone()).or_default();
        queue.push_back(entry);
        if queue.len() > MAX_BUFFERED_SENDS_PER_ENDPOINT {
            queue.pop_front();
            warn!(
                "Retransmit buffer for {:?} exceeded {} entries, dropping the oldest message; \
                 it can no longer be recovered if the peer loses its session",
                endpoint, MAX_BUFFERED_SENDS_PER_ENDPOINT
            );
        }
    }

    /// Drains the endpoint's buffer and returns, in message-id order
    pub(super) fn take_from(
        &mut self,
        endpoint: &Endpoint,
        session_id: &SessionId,
        first_lost_message_id: u64,
    ) -> Vec<BufferedSend> {
        let Some(queue) = self.entries.remove(endpoint) else {
            return Vec::new();
        };
        let mut lost: Vec<BufferedSend> = queue
            .into_iter()
            .filter(|entry| {
                &entry.session_id == session_id
                    && entry.message_id >= first_lost_message_id
                    && entry.retransmissions < MAX_RETRANSMISSIONS
            })
            .collect();
        lost.sort_by_key(|entry| entry.message_id);
        lost
    }

    /// Drops all buffered entries for the endpoint
    pub(super) fn clear_endpoint(&mut self, endpoint: &Endpoint) {
        self.entries.remove(endpoint);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_provider::noise::transport_state::SESSION_ID_SIZE;

    const ENDPOINT: Endpoint = Endpoint::DesktopMain;
    const OTHER_ENDPOINT: Endpoint = Endpoint::DesktopRenderer;

    fn session(byte: u8) -> SessionId {
        SessionId([byte; SESSION_ID_SIZE])
    }

    fn entry(session_id: SessionId, message_id: u64) -> BufferedSend {
        BufferedSend {
            payload: Zeroizing::new(format!("msg-{message_id}").into_bytes()),
            topic: None,
            session_id,
            message_id,
            retransmissions: 0,
        }
    }

    #[test]
    fn message_ids_increment_per_endpoint() {
        let mut buffer = RetransmitBuffer::default();

        assert_eq!(buffer.next_message_id(&ENDPOINT), 1);
        assert_eq!(buffer.next_message_id(&ENDPOINT), 2);
        // A different endpoint has its own counter.
        assert_eq!(buffer.next_message_id(&OTHER_ENDPOINT), 1);
        assert_eq!(buffer.next_message_id(&ENDPOINT), 3);
    }

    #[test]
    fn take_from_returns_only_lost_messages_of_the_session_in_order() {
        let mut buffer = RetransmitBuffer::default();
        buffer.record(ENDPOINT, entry(session(1), 1));
        buffer.record(ENDPOINT, entry(session(1), 2));
        buffer.record(ENDPOINT, entry(session(2), 3)); // different session: stale
        buffer.record(ENDPOINT, entry(session(1), 4));

        let lost = buffer.take_from(&ENDPOINT, &session(1), 2);

        let ids: Vec<u64> = lost.iter().map(|e| e.message_id).collect();
        assert_eq!(ids, vec![2, 4], "id 1 was delivered, id 3 is stale");
        // The buffer is drained: a second invalidation finds nothing.
        assert!(buffer.take_from(&ENDPOINT, &session(1), 0).is_empty());
    }

    #[test]
    fn take_from_with_legacy_zero_id_returns_everything_for_the_session() {
        let mut buffer = RetransmitBuffer::default();
        buffer.record(ENDPOINT, entry(session(1), 1));
        buffer.record(ENDPOINT, entry(session(1), 2));

        let lost = buffer.take_from(&ENDPOINT, &session(1), 0);

        assert_eq!(lost.len(), 2);
    }

    #[test]
    fn take_from_skips_entries_that_exhausted_their_retransmission_budget() {
        let mut buffer = RetransmitBuffer::default();
        let mut exhausted = entry(session(1), 1);
        exhausted.retransmissions = MAX_RETRANSMISSIONS;
        buffer.record(ENDPOINT, exhausted);
        buffer.record(ENDPOINT, entry(session(1), 2));

        let lost = buffer.take_from(&ENDPOINT, &session(1), 0);

        let ids: Vec<u64> = lost.iter().map(|e| e.message_id).collect();
        assert_eq!(ids, vec![2]);
    }

    #[test]
    fn record_evicts_the_oldest_entry_over_the_cap() {
        let mut buffer = RetransmitBuffer::default();
        for id in 1..=(MAX_BUFFERED_SENDS_PER_ENDPOINT as u64 + 1) {
            buffer.record(ENDPOINT, entry(session(1), id));
        }

        let lost = buffer.take_from(&ENDPOINT, &session(1), 0);

        assert_eq!(lost.len(), MAX_BUFFERED_SENDS_PER_ENDPOINT);
        assert_eq!(
            lost.first().map(|e| e.message_id),
            Some(2),
            "the oldest entry (id 1) must have been evicted"
        );
    }

    #[test]
    fn clear_endpoint_drops_entries_but_keeps_the_counter() {
        let mut buffer = RetransmitBuffer::default();
        assert_eq!(buffer.next_message_id(&ENDPOINT), 1);
        buffer.record(ENDPOINT, entry(session(1), 1));

        buffer.clear_endpoint(&ENDPOINT);

        assert!(buffer.take_from(&ENDPOINT, &session(1), 0).is_empty());
        assert_eq!(
            buffer.next_message_id(&ENDPOINT),
            2,
            "the counter must never go backwards"
        );
    }
}
