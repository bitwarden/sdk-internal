use std::{collections::HashMap, sync::Mutex, time::Duration};

use thiserror::Error;
use web_time::Instant;

use super::{FRAGMENT_TOPIC, FragmentFrame, FragmentHeader, MAX_PAYLOAD_SIZE, OriginalTopic};
use crate::{endpoint::Source, message::IncomingMessage};

/// Time after the first fragment at which an incomplete message is discarded.
pub(crate) const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(10);

/// Time without a new fragment after which an incomplete message is discarded, so a sender that
/// stops mid-message frees its reservation before [`REASSEMBLY_TIMEOUT`]. Well above the Noise
/// handshake timeout, because a handshake on either side delays fragment processing that long.
pub(crate) const REASSEMBLY_IDLE_TIMEOUT: Duration = Duration::from_secs(5);

/// Most incomplete messages and reserved bytes for a single source.
const SOURCE_LIMIT: Usage = Usage {
    messages: 4,
    bytes: MAX_PAYLOAD_SIZE,
};

/// Most incomplete messages and reserved bytes across all non-web sources.
const OTHER_POOL_LIMIT: Usage = Usage {
    messages: 16,
    bytes: 4 * MAX_PAYLOAD_SIZE,
};

/// Most incomplete messages and reserved bytes across all web sources.
const WEB_POOL_LIMIT: Usage = Usage {
    messages: 4,
    bytes: MAX_PAYLOAD_SIZE,
};

/// Reason a fragment was dropped by [`Reassembler::accept`].
#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum ReassemblyError {
    #[error("Malformed fragment header")]
    Malformed,
    #[error("Fragment header is out of bounds")]
    InvalidHeader,
    #[error("Fragment arrived out of order")]
    OutOfOrder,
    #[error("Too many incomplete messages")]
    TooManyPartialMessages,
    #[error("Reassembly buffer is full")]
    BufferFull,
    #[error("Reassembly buffer for this source is full")]
    SourceBufferFull,
    #[error("Fragment does not match earlier fragments of the same message")]
    Inconsistent,
}

/// Fragments of one message are only ever combined with fragments from the same source.
type MessageKey = (Source, u64);

/// Incomplete messages and the bytes reserved for them, counted by their declared total size.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Usage {
    messages: usize,
    bytes: usize,
}

/// Group of sources that share the limits on incomplete messages.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pool {
    Web,
    Other,
}

impl Pool {
    fn of(source: &Source) -> Self {
        match source {
            Source::Web { .. } => Pool::Web,
            _ => Pool::Other,
        }
    }

    fn limit(self) -> Usage {
        match self {
            Pool::Web => WEB_POOL_LIMIT,
            Pool::Other => OTHER_POOL_LIMIT,
        }
    }
}

struct PartialMessage {
    /// [`REASSEMBLY_TIMEOUT`] after the first fragment.
    deadline: Instant,
    /// Time at which the message is discarded if still incomplete: the earlier of `deadline` and
    /// [`REASSEMBLY_IDLE_TIMEOUT`] after the last fragment.
    expires_at: Instant,
    total_len: usize,
    topic: OriginalTopic,
    next_index: u32,
    /// Grows with the received data, so a peer that declares a large size without sending it
    /// does not hold that memory.
    payload: Vec<u8>,
}

impl PartialMessage {
    /// Returns an error if a fragment cannot be the next one of this message.
    fn check(
        &self,
        header: &FragmentHeader,
        topic: &OriginalTopic,
        data_len: usize,
    ) -> Result<(), ReassemblyError> {
        if header.index != self.next_index {
            return Err(ReassemblyError::OutOfOrder);
        }
        if header.total_len as usize != self.total_len
            || *topic != self.topic
            || self.payload.len() + data_len > self.total_len
        {
            return Err(ReassemblyError::Inconsistent);
        }
        Ok(())
    }

    fn append(&mut self, data: &[u8]) {
        let needed = self.payload.len() + data.len();
        if needed > self.payload.capacity() {
            // Grow geometrically, but never past the declared size.
            let target = (self.payload.capacity() * 2)
                .max(needed)
                .min(self.total_len);
            self.payload.reserve_exact(target - self.payload.len());
        }
        self.payload.extend_from_slice(data);
        self.next_index += 1;
    }

    fn is_complete(&self) -> bool {
        self.payload.len() == self.total_len
    }
}

#[derive(Default)]
struct ReassemblyState {
    partials: HashMap<MessageKey, PartialMessage>,
}

impl ReassemblyState {
    fn usage(&self, filter: impl Fn(&Source) -> bool) -> Usage {
        self.partials
            .iter()
            .filter(|((source, _), _)| filter(source))
            .fold(Usage::default(), |usage, (_, p)| Usage {
                messages: usage.messages + 1,
                bytes: usage.bytes + p.total_len,
            })
    }

    /// Returns an error if `source` cannot start another incomplete message of `total_len` bytes.
    fn admit(&self, source: &Source, total_len: usize) -> Result<(), ReassemblyError> {
        let pool = Pool::of(source);
        let pool_limit = pool.limit();
        let source_usage = self.usage(|s| s == source);
        let pool_usage = self.usage(|s| Pool::of(s) == pool);

        if source_usage.messages >= SOURCE_LIMIT.messages
            || pool_usage.messages >= pool_limit.messages
        {
            return Err(ReassemblyError::TooManyPartialMessages);
        }
        if source_usage.bytes + total_len > SOURCE_LIMIT.bytes {
            return Err(ReassemblyError::SourceBufferFull);
        }
        if pool_usage.bytes + total_len > pool_limit.bytes {
            return Err(ReassemblyError::BufferFull);
        }
        Ok(())
    }

    fn remove_expired(&mut self, now: Instant) {
        self.partials.retain(|(source, _), partial| {
            let keep = partial.expires_at > now;
            if !keep {
                tracing::warn!(?source, "Discarding incomplete IPC message after timeout");
            }
            keep
        });
    }
}

/// Reassembles fragmented messages received from untrusted peers.
pub(crate) struct Reassembler {
    state: Mutex<ReassemblyState>,
    timeout: Duration,
    idle_timeout: Duration,
}

impl Reassembler {
    /// Creates a reassembler that discards incomplete messages `timeout` after their first
    /// fragment, or earlier when no fragment arrives for `idle_timeout`. Expired messages are
    /// discarded when the next fragment from any source arrives.
    pub(crate) fn new(timeout: Duration, idle_timeout: Duration) -> Self {
        Self {
            state: Mutex::default(),
            timeout,
            idle_timeout,
        }
    }

    /// Returns `None` if `topic` does not mark a fragment, otherwise the topic of the message the
    /// fragment belongs to.
    pub(super) fn original_topic(topic: Option<&str>) -> Option<OriginalTopic> {
        let rest = topic?.strip_prefix(FRAGMENT_TOPIC)?;
        if rest.is_empty() {
            return Some(None);
        }
        rest.strip_prefix('/').map(|t| Some(t.to_owned()))
    }

    /// Passes non-fragment messages through, and returns a reassembled message once its last
    /// fragment arrives. Invalid fragments are logged and dropped.
    pub(crate) fn process(&self, message: IncomingMessage) -> Option<IncomingMessage> {
        let Some(topic) = Self::original_topic(message.topic.as_deref()) else {
            return Some(message);
        };
        let source = message.source.clone();
        self.accept(message, topic, Instant::now())
            .unwrap_or_else(|error| {
                tracing::warn!(%error, ?source, "Dropping invalid IPC fragment");
                None
            })
    }

    /// Appends one fragment received at `now` and returns the reassembled message once the last
    /// fragment arrived. Any inconsistency discards the whole incomplete message.
    fn accept(
        &self,
        message: IncomingMessage,
        topic: OriginalTopic,
        now: Instant,
    ) -> Result<Option<IncomingMessage>, ReassemblyError> {
        let FragmentFrame { header, data } =
            FragmentFrame::decode(&message.payload).ok_or(ReassemblyError::Malformed)?;

        let total_len = header.total_len as usize;
        // Every fragment carries data, so a message has at most `total_len` fragments.
        if total_len > MAX_PAYLOAD_SIZE || data.is_empty() {
            return Err(ReassemblyError::InvalidHeader);
        }

        let key = (message.source, header.message_id);
        let mut state = self.state.lock().expect("Failed to lock reassembly state");
        state.remove_expired(now);

        if !state.partials.contains_key(&key) {
            if header.index != 0 {
                return Err(ReassemblyError::OutOfOrder);
            }
            state.admit(&key.0, total_len)?;
            let deadline = now + self.timeout;
            state.partials.insert(
                key.clone(),
                PartialMessage {
                    deadline,
                    expires_at: deadline,
                    total_len,
                    topic: topic.clone(),
                    next_index: 0,
                    payload: Vec::new(),
                },
            );
        }

        let partial = state
            .partials
            .get_mut(&key)
            .expect("Partial message was just checked or inserted");
        if let Err(error) = partial.check(&header, &topic, data.len()) {
            state.partials.remove(&key);
            return Err(error);
        }
        partial.append(data);
        partial.expires_at = partial.deadline.min(now + self.idle_timeout);
        if !partial.is_complete() {
            return Ok(None);
        }

        let partial = state
            .partials
            .remove(&key)
            .expect("Partial message was just updated");
        Ok(Some(IncomingMessage {
            payload: partial.payload,
            destination: message.destination,
            source: key.0,
            topic: partial.topic,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::{super::test_support::*, *};
    use crate::{fragmentation::Fragments, message::OutgoingMessage};

    /// Larger than several Noise messages, and not a multiple of the fragment size.
    const LARGE_LEN: usize = 4 * 65535 + 123;

    impl Reassembler {
        fn pending(&self) -> Usage {
            self.state.lock().unwrap().usage(|_| true)
        }

        /// Accepts a fragment now, taking the original topic from its prefixed topic.
        fn accept_fragment(
            &self,
            message: IncomingMessage,
        ) -> Result<Option<IncomingMessage>, ReassemblyError> {
            self.accept_fragment_at(message, Instant::now())
        }

        /// Accepts a fragment received at `now`.
        fn accept_fragment_at(
            &self,
            message: IncomingMessage,
            now: Instant,
        ) -> Result<Option<IncomingMessage>, ReassemblyError> {
            let topic = Reassembler::original_topic(message.topic.as_deref())
                .expect("Not a fragment topic");
            self.accept(message, topic, now)
        }

        /// Accepts the first fragment of a crafted message.
        fn accept_first(
            &self,
            source: Source,
            message_id: u64,
            total_len: usize,
        ) -> Result<Option<IncomingMessage>, ReassemblyError> {
            self.accept_fragment(crafted(source, message_id, 0, total_len))
        }
    }

    fn usage(messages: usize, bytes: usize) -> Usage {
        Usage { messages, bytes }
    }

    #[test]
    fn interleaved_fragments_of_concurrent_messages_reassemble() {
        let reassembler = Reassembler::new(REASSEMBLY_TIMEOUT, REASSEMBLY_IDLE_TIMEOUT);
        let payload_a = large_payload(LARGE_LEN, 1);
        let payload_b = large_payload(LARGE_LEN - 1000, 2);
        let fragments_a = split_all(outgoing(payload_a.clone(), "a"), MAX_LEN);
        let fragments_b = split_all(outgoing(payload_b.clone(), "b"), MAX_LEN);

        let mut completed = Vec::new();
        for i in 0..fragments_a.len().max(fragments_b.len()) {
            for fragment in [fragments_a.get(i), fragments_b.get(i)]
                .into_iter()
                .flatten()
            {
                completed.extend(reassembler.process(incoming(fragment.clone(), web_source(1))));
            }
        }

        // B has fewer fragments, so it completes first.
        assert_eq!(completed.len(), 2);
        assert_eq!(completed[0].topic.as_deref(), Some("b"));
        assert_eq!(completed[0].payload, payload_b);
        assert_eq!(completed[1].topic.as_deref(), Some("a"));
        assert_eq!(completed[1].payload, payload_a);
        assert_eq!(reassembler.pending(), Usage::default());
    }

    #[test]
    fn fragments_from_different_sources_do_not_mix() {
        let reassembler = Reassembler::new(REASSEMBLY_TIMEOUT, REASSEMBLY_IDLE_TIMEOUT);
        let payload = large_payload(FRAGMENT_LEN * 2, 0);
        let fragments = split_all(outgoing(payload.clone(), "bulk"), MAX_LEN);

        // The same message id from two sources starts two separate messages.
        for tab_id in [1, 2] {
            assert!(
                reassembler
                    .process(incoming(fragments[0].clone(), web_source(tab_id)))
                    .is_none()
            );
        }
        assert_eq!(reassembler.pending().messages, 2);

        let completed = reassembler
            .process(incoming(fragments[1].clone(), web_source(2)))
            .unwrap();
        assert_eq!(completed.source, web_source(2));
        assert_eq!(completed.payload, payload);
        assert_eq!(reassembler.pending().messages, 1);
    }

    #[test]
    fn out_of_order_fragment_discards_its_message() {
        let reassembler = Reassembler::new(REASSEMBLY_TIMEOUT, REASSEMBLY_IDLE_TIMEOUT);
        let source = web_source(1);
        let payload = large_payload(FRAGMENT_LEN * 3, 0);
        let fragments = split_all(outgoing(payload, "bulk"), MAX_LEN);
        let accept =
            |i: usize| reassembler.accept_fragment(incoming(fragments[i].clone(), source.clone()));

        // A message cannot start after its first fragment.
        assert_eq!(accept(1), Err(ReassemblyError::OutOfOrder));
        assert_eq!(reassembler.pending(), Usage::default());

        // A gap or a repeated fragment discards the message.
        assert_eq!(accept(0), Ok(None));
        assert_eq!(accept(2), Err(ReassemblyError::OutOfOrder));
        assert_eq!(reassembler.pending(), Usage::default());
        assert_eq!(accept(0), Ok(None));
        assert_eq!(accept(0), Err(ReassemblyError::OutOfOrder));
        assert_eq!(reassembler.pending(), Usage::default());
    }

    #[test]
    fn invalid_fragments_are_rejected_and_discard_their_message() {
        let reassembler = Reassembler::new(REASSEMBLY_TIMEOUT, REASSEMBLY_IDLE_TIMEOUT);
        let source = web_source(1);
        let accept = |message_id: u64, index: u32, total_len: usize| {
            reassembler.accept_fragment(crafted(source.clone(), message_id, index, total_len))
        };
        let accept_payload = |payload: Vec<u8>, topic: &str| {
            reassembler.accept_fragment(incoming(outgoing(payload, topic), source.clone()))
        };

        let mut garbage = vec![0xff; 8];
        garbage[0] = 0x1f;
        assert_eq!(
            accept_payload(garbage, FRAGMENT_TOPIC),
            Err(ReassemblyError::Malformed)
        );
        assert_eq!(
            accept(1, 0, MAX_PAYLOAD_SIZE + 1),
            Err(ReassemblyError::InvalidHeader)
        );
        let empty = FragmentFrame {
            header: FragmentHeader {
                message_id: 1,
                index: 0,
                total_len: 1024,
            },
            data: &[],
        }
        .encode();
        assert_eq!(
            accept_payload(empty, &Fragments::fragment_topic(Some("bulk"))),
            Err(ReassemblyError::InvalidHeader)
        );
        assert_eq!(reassembler.pending(), Usage::default());

        // Each of these first buffers a valid fragment, then sends one that conflicts with it.
        assert_eq!(accept(2, 0, 1024), Ok(None));
        assert_eq!(accept(2, 1, 2048), Err(ReassemblyError::Inconsistent));
        assert_eq!(reassembler.pending(), Usage::default());

        assert_eq!(accept(3, 0, 20), Ok(None));
        assert_eq!(accept(3, 1, 20), Err(ReassemblyError::Inconsistent));
        assert_eq!(reassembler.pending(), Usage::default());

        assert_eq!(accept(4, 0, 1024), Ok(None));
        let other_topic = FragmentFrame {
            header: FragmentHeader {
                message_id: 4,
                index: 1,
                total_len: 1024,
            },
            data: &[0; 16],
        }
        .encode();
        assert_eq!(
            accept_payload(other_topic, &Fragments::fragment_topic(Some("other"))),
            Err(ReassemblyError::Inconsistent)
        );
        assert_eq!(reassembler.pending(), Usage::default());

        // The message completes once the declared size has arrived.
        assert_eq!(accept(5, 0, 32), Ok(None));
        let completed = accept(5, 1, 32).unwrap().unwrap();
        assert_eq!(completed.payload.len(), 32);
        assert_eq!(completed.topic.as_deref(), Some("bulk"));
        assert_eq!(reassembler.pending(), Usage::default());
    }

    #[test]
    fn incomplete_messages_are_bounded_per_source_and_per_pool() {
        let reassembler = Reassembler::new(REASSEMBLY_TIMEOUT, REASSEMBLY_IDLE_TIMEOUT);
        let source = foreground_source;

        for message_id in 0..SOURCE_LIMIT.messages as u64 {
            assert_eq!(
                reassembler.accept_first(source(0), message_id, 1024),
                Ok(None)
            );
        }
        assert_eq!(
            reassembler.accept_first(source(0), 99, 1024),
            Err(ReassemblyError::TooManyPartialMessages)
        );

        // Other sources fill the remaining slots of the pool.
        for id in 1..=(OTHER_POOL_LIMIT.messages - SOURCE_LIMIT.messages) as i32 {
            assert_eq!(reassembler.accept_first(source(id), 0, 1024), Ok(None));
        }
        assert_eq!(
            reassembler.accept_first(source(100), 0, 1024),
            Err(ReassemblyError::TooManyPartialMessages)
        );
        assert_eq!(reassembler.pending().messages, OTHER_POOL_LIMIT.messages);
    }

    #[test]
    fn declared_sizes_are_reserved_per_source_and_per_pool() {
        let source = foreground_source;

        // Declared sizes are reserved before any data is buffered.
        let reassembler = Reassembler::new(REASSEMBLY_TIMEOUT, REASSEMBLY_IDLE_TIMEOUT);
        for id in 0..(OTHER_POOL_LIMIT.bytes / MAX_PAYLOAD_SIZE) as i32 {
            assert_eq!(
                reassembler.accept_first(source(id), 0, MAX_PAYLOAD_SIZE),
                Ok(None)
            );
        }
        assert_eq!(
            reassembler.accept_first(source(100), 0, 1024),
            Err(ReassemblyError::BufferFull)
        );
        assert_eq!(reassembler.pending().bytes, OTHER_POOL_LIMIT.bytes);

        // One source cannot reserve more than its cap, while another source still can.
        let reassembler = Reassembler::new(REASSEMBLY_TIMEOUT, REASSEMBLY_IDLE_TIMEOUT);
        let half = SOURCE_LIMIT.bytes / 2;
        assert_eq!(reassembler.accept_first(source(0), 0, half), Ok(None));
        assert_eq!(reassembler.accept_first(source(0), 1, half), Ok(None));
        assert_eq!(
            reassembler.accept_first(source(0), 2, 1024),
            Err(ReassemblyError::SourceBufferFull)
        );
        assert_eq!(
            reassembler.accept_first(source(1), 0, MAX_PAYLOAD_SIZE),
            Ok(None)
        );
        assert_eq!(reassembler.pending(), usage(3, 2 * MAX_PAYLOAD_SIZE));
    }

    #[test]
    fn web_sources_cannot_exhaust_the_pool_of_other_sources() {
        let reassembler = Reassembler::new(REASSEMBLY_TIMEOUT, REASSEMBLY_IDLE_TIMEOUT);

        // Many distinct web sources only fill the web pool's slots.
        for tab_id in 0..WEB_POOL_LIMIT.messages as i32 {
            assert_eq!(
                reassembler.accept_first(web_source(tab_id), 0, 1024),
                Ok(None)
            );
        }
        for tab_id in 100..120 {
            assert_eq!(
                reassembler.accept_first(web_source(tab_id), 0, 1024),
                Err(ReassemblyError::TooManyPartialMessages)
            );
        }
        assert_eq!(
            reassembler.accept_first(foreground_source(0), 0, MAX_PAYLOAD_SIZE),
            Ok(None)
        );

        // A web source declaring the maximum size fills the web pool's bytes.
        let reassembler = Reassembler::new(REASSEMBLY_TIMEOUT, REASSEMBLY_IDLE_TIMEOUT);
        assert_eq!(
            reassembler.accept_first(web_source(0), 0, WEB_POOL_LIMIT.bytes),
            Ok(None)
        );
        assert_eq!(
            reassembler.accept_first(web_source(1), 0, 1024),
            Err(ReassemblyError::BufferFull)
        );
        assert_eq!(
            reassembler.accept_first(foreground_source(0), 0, MAX_PAYLOAD_SIZE),
            Ok(None)
        );
    }

    #[test]
    fn buffer_grows_with_received_data_up_to_declared_size() {
        let reassembler = Reassembler::new(REASSEMBLY_TIMEOUT, REASSEMBLY_IDLE_TIMEOUT);
        let capacity = |source: &Source| {
            let state = reassembler.state.lock().unwrap();
            let (_, partial) = state
                .partials
                .iter()
                .find(|((s, _), _)| s == source)
                .unwrap();
            partial.payload.capacity()
        };

        // Declaring the maximum size does not allocate it.
        let idle = foreground_source(0);
        assert_eq!(
            reassembler.accept_first(idle.clone(), 0, MAX_PAYLOAD_SIZE),
            Ok(None)
        );
        assert!(capacity(&idle) < 1024);

        let source = foreground_source(1);
        let payload = large_payload(LARGE_LEN, 0);
        let fragments = split_all(outgoing(payload.clone(), "bulk"), MAX_LEN);
        let (last, rest) = fragments.split_last().unwrap();
        for fragment in rest {
            assert!(
                reassembler
                    .process(incoming(fragment.clone(), source.clone()))
                    .is_none()
            );
        }
        assert!(capacity(&source) <= LARGE_LEN);

        let completed = reassembler.process(incoming(last.clone(), source)).unwrap();
        assert_eq!(completed.payload, payload);
        assert_eq!(completed.payload.capacity(), LARGE_LEN);
    }

    #[test]
    fn incomplete_message_expires_and_frees_its_slot() {
        let reassembler = Reassembler::new(REASSEMBLY_TIMEOUT, REASSEMBLY_IDLE_TIMEOUT);
        let source = foreground_source(0);
        let start = Instant::now();
        let accept_first = |message_id: u64| {
            reassembler.accept_fragment_at(crafted(source.clone(), message_id, 0, 1024), start)
        };

        for message_id in 0..SOURCE_LIMIT.messages as u64 {
            assert_eq!(accept_first(message_id), Ok(None));
        }
        assert_eq!(
            accept_first(99),
            Err(ReassemblyError::TooManyPartialMessages)
        );

        // The next fragment from any source discards the expired messages first.
        let later = start + REASSEMBLY_IDLE_TIMEOUT;
        assert_eq!(
            reassembler.accept_fragment_at(crafted(source.clone(), 0, 1, 1024), later),
            Err(ReassemblyError::OutOfOrder)
        );
        assert_eq!(reassembler.pending(), Usage::default());
        assert_eq!(
            reassembler.accept_fragment_at(crafted(source, 99, 0, 1024), later),
            Ok(None)
        );
    }

    #[test]
    fn message_without_topic_reassembles_without_topic() {
        let reassembler = Reassembler::new(REASSEMBLY_TIMEOUT, REASSEMBLY_IDLE_TIMEOUT);
        let payload = large_payload(LARGE_LEN, 3);
        let message = OutgoingMessage {
            topic: None,
            ..outgoing(payload.clone(), "unused")
        };

        let completed: Vec<_> = split_all(message, MAX_LEN)
            .into_iter()
            .filter_map(|f| reassembler.process(incoming(f, web_source(1))))
            .collect();

        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].topic, None);
        assert_eq!(completed[0].payload, payload);
    }

    #[test]
    fn largest_payload_from_a_web_source_reassembles_and_frees_its_reservation() {
        let reassembler = Reassembler::new(REASSEMBLY_TIMEOUT, REASSEMBLY_IDLE_TIMEOUT);
        let payload = large_payload(MAX_PAYLOAD_SIZE, 4);
        let mut fragments = split_all(outgoing(payload.clone(), "bulk"), MAX_LEN).into_iter();

        // The largest payload reserves the whole web pool.
        assert!(
            reassembler
                .process(incoming(fragments.next().unwrap(), web_source(1)))
                .is_none()
        );
        assert_eq!(
            reassembler.accept_first(web_source(2), 0, 1024),
            Err(ReassemblyError::BufferFull)
        );

        let completed: Vec<_> = fragments
            .filter_map(|f| reassembler.process(incoming(f, web_source(1))))
            .collect();
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].payload, payload);

        // Completing the message frees its reservation.
        assert_eq!(reassembler.accept_first(web_source(2), 0, 1024), Ok(None));
    }

    #[test]
    fn each_fragment_extends_the_idle_timeout() {
        let reassembler = Reassembler::new(REASSEMBLY_TIMEOUT, REASSEMBLY_IDLE_TIMEOUT);
        let source = foreground_source(0);
        let fragments = split_all(
            outgoing(large_payload(FRAGMENT_LEN * 4, 0), "bulk"),
            MAX_LEN,
        );
        let accept = |i: usize, at: Instant| {
            reassembler.accept_fragment_at(incoming(fragments[i].clone(), source.clone()), at)
        };
        let gap = REASSEMBLY_IDLE_TIMEOUT - Duration::from_millis(1);
        let start = Instant::now();

        // Each fragment arrives just within the idle timeout of the previous one.
        assert_eq!(accept(0, start), Ok(None));
        assert_eq!(accept(1, start + gap), Ok(None));
        assert_eq!(accept(2, start + gap * 2), Ok(None));

        let last = start + gap * 2;
        assert_eq!(
            accept(3, last + REASSEMBLY_IDLE_TIMEOUT),
            Err(ReassemblyError::OutOfOrder)
        );
        assert_eq!(reassembler.pending(), Usage::default());
    }

    #[test]
    fn steady_fragments_cannot_outlive_the_overall_timeout() {
        let reassembler = Reassembler::new(REASSEMBLY_TIMEOUT, REASSEMBLY_IDLE_TIMEOUT);
        let source = foreground_source(0);
        let fragments = split_all(
            outgoing(large_payload(FRAGMENT_LEN * 8, 0), "bulk"),
            MAX_LEN,
        );
        let accept = |i: usize, at: Instant| {
            reassembler.accept_fragment_at(incoming(fragments[i].clone(), source.clone()), at)
        };
        let gap = REASSEMBLY_IDLE_TIMEOUT / 2;
        let start = Instant::now();

        // Every gap is within the idle timeout, but the message expires at the overall timeout.
        let mut index = 0;
        while gap * index < REASSEMBLY_TIMEOUT {
            assert_eq!(accept(index as usize, start + gap * index), Ok(None));
            index += 1;
        }
        assert_eq!(
            accept(index as usize, start + gap * index),
            Err(ReassemblyError::OutOfOrder)
        );
    }
}
