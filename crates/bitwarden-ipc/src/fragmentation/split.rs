use rand::RngExt;
use thiserror::Error;

use super::{FRAGMENT_TOPIC, FragmentHeader, MAX_HEADER_LEN, MAX_PAYLOAD_SIZE, Reassembler};
use crate::message::OutgoingMessage;

/// Error returned by [`Fragments::split`] when a message cannot be sent.
#[derive(Debug, Error)]
pub(crate) enum FragmentationError {
    #[error("Payload of {0} bytes exceeds the maximum of {MAX_PAYLOAD_SIZE} bytes")]
    PayloadTooLarge(usize),
    #[error("Crypto provider message limit of {0} bytes leaves no room for fragment data")]
    ProviderLimitTooSmall(usize),
    #[error("Topic {0:?} is reserved for fragments")]
    ReservedTopic(String),
}

/// Messages that carry one outgoing message, encoded one at a time as they are sent.
pub(crate) enum Fragments {
    Single(Option<OutgoingMessage>),
    Many {
        message: OutgoingMessage,
        message_id: u64,
        topic: String,
        fragment_len: usize,
        next_index: u32,
    },
}

impl Fragments {
    /// Returns the message unchanged if its payload fits in one message of at most
    /// `max_payload_len` bytes, otherwise fragments that each fit in one.
    pub(crate) fn split(
        message: OutgoingMessage,
        max_payload_len: usize,
    ) -> Result<Self, FragmentationError> {
        // The receiver would treat such a message as a fragment and drop it.
        if let Some(topic) = &message.topic
            && Reassembler::original_topic(Some(topic)).is_some()
        {
            return Err(FragmentationError::ReservedTopic(topic.clone()));
        }

        let total_len = message.payload.len();
        if total_len > MAX_PAYLOAD_SIZE {
            return Err(FragmentationError::PayloadTooLarge(total_len));
        }
        if total_len <= max_payload_len {
            return Ok(Fragments::Single(Some(message)));
        }
        let fragment_len = max_payload_len.saturating_sub(MAX_HEADER_LEN);
        if fragment_len == 0 {
            return Err(FragmentationError::ProviderLimitTooSmall(max_payload_len));
        }

        Ok(Fragments::Many {
            message_id: bitwarden_random::rng().random(),
            topic: Self::fragment_topic(message.topic.as_deref()),
            message,
            fragment_len,
            next_index: 0,
        })
    }

    /// Returns the topic carried by the fragments of a message with `topic`.
    pub(super) fn fragment_topic(topic: Option<&str>) -> String {
        match topic {
            Some(topic) => format!("{FRAGMENT_TOPIC}/{topic}"),
            None => FRAGMENT_TOPIC.to_owned(),
        }
    }
}

impl Iterator for Fragments {
    type Item = OutgoingMessage;

    fn next(&mut self) -> Option<OutgoingMessage> {
        match self {
            Fragments::Single(message) => message.take(),
            Fragments::Many {
                message,
                message_id,
                topic,
                fragment_len,
                next_index,
            } => {
                let total_len = message.payload.len();
                let start = *next_index as usize * *fragment_len;
                if start >= total_len {
                    return None;
                }
                let end = total_len.min(start + *fragment_len);
                // Both fit in a u32 because `total_len` is at most `MAX_PAYLOAD_SIZE`.
                let header = FragmentHeader {
                    message_id: *message_id,
                    index: *next_index,
                    total_len: total_len as u32,
                };
                *next_index += 1;
                Some(OutgoingMessage {
                    payload: header.encode(&message.payload[start..end]),
                    destination: message.destination.clone(),
                    topic: Some(topic.clone()),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{super::test_support::*, *};

    #[test]
    fn payload_within_provider_limit_is_sent_as_one_unchanged_message() {
        let small = outgoing(large_payload(MAX_LEN, 0), "bulk");
        assert_eq!(split_all(small.clone(), MAX_LEN), vec![small]);

        let fragments = split_all(outgoing(large_payload(MAX_LEN + 1, 0), "bulk"), MAX_LEN);
        assert_eq!(fragments.len(), 2);
        assert!(fragments.iter().all(|m| {
            m.topic.as_deref() == Some("IpcFragment/bulk") && m.payload.len() <= MAX_LEN
        }));
    }

    #[test]
    fn split_rejects_payloads_it_cannot_fragment() {
        // The limit applies even when the provider could send the payload in one message.
        for provider_limit in [MAX_LEN, usize::MAX] {
            assert!(matches!(
                Fragments::split(
                    outgoing(vec![0; MAX_PAYLOAD_SIZE + 1], "bulk"),
                    provider_limit
                ),
                Err(FragmentationError::PayloadTooLarge(_))
            ));
        }
        assert!(matches!(
            Fragments::split(outgoing(vec![0; 2048], "bulk"), MAX_HEADER_LEN),
            Err(FragmentationError::ProviderLimitTooSmall(_))
        ));
    }

    #[test]
    fn split_rejects_reserved_topics_even_for_small_payloads() {
        for topic in [FRAGMENT_TOPIC, "IpcFragment/bulk"] {
            assert!(matches!(
                Fragments::split(outgoing(vec![0; 16], topic), MAX_LEN),
                Err(FragmentationError::ReservedTopic(_))
            ));
        }
        assert!(Fragments::split(outgoing(vec![0; 16], "IpcFragments"), MAX_LEN).is_ok());
    }
}
