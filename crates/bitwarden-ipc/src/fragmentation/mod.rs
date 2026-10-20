//! Splits payloads larger than one crypto provider message into fragments and reassembles them on
//! the receiving side.
//!
//! Fragmentation runs above the [`CryptoProvider`](crate::traits::CryptoProvider), so each fragment
//! is an ordinary [`OutgoingMessage`](crate::message::OutgoingMessage) that the provider encrypts
//! on its own. A fragment's topic is the original topic behind the reserved [`FRAGMENT_TOPIC`]
//! prefix, and its payload is a [`FragmentFrame`]: a CBOR [`FragmentHeader`] followed by the raw
//! fragment data, so the data is copied once on each side. Peers without fragmentation support
//! deliver such messages to subscribers as an unknown topic.
//!
//! The sender awaits each fragment before sending the next and the communication backends deliver
//! in order, so fragments are appended as they arrive and any gap discards the message.
//!
//! Every peer is untrusted, so the [`Reassembler`] bounds the reassembled size, and the number of
//! incomplete messages and the bytes reserved for them, both per source and per pool. Web pages are
//! numerous and untrusted, so all web sources share a smaller pool that cannot consume the pool of
//! the other sources. An incomplete message is discarded when no fragment arrives for
//! [`REASSEMBLY_IDLE_TIMEOUT`], or [`REASSEMBLY_TIMEOUT`] after its first fragment.

mod reassembler;
mod split;

pub(crate) use reassembler::{REASSEMBLY_IDLE_TIMEOUT, REASSEMBLY_TIMEOUT, Reassembler};
use serde::{Deserialize, Serialize};
pub(crate) use split::{FragmentationError, Fragments};

/// Reserved topic that marks a message as a fragment. A fragment of a message with a topic carries
/// `IpcFragment/<topic>`.
pub(crate) const FRAGMENT_TOPIC: &str = "IpcFragment";

/// Largest payload that can be sent, and the largest reassembled payload a receiver accepts. IPC is
/// meant for messages, so larger data has to be streamed some other way.
pub(crate) const MAX_PAYLOAD_SIZE: usize = 5 * 1024 * 1024;

/// Upper bound on the encoded size of a [`FragmentHeader`].
const MAX_HEADER_LEN: usize = 128;

/// Metadata that identifies a fragment within its message.
#[derive(Debug, Serialize, Deserialize)]
struct FragmentHeader {
    /// Random per message, so fragments of concurrent sends from one sender don't mix.
    message_id: u64,
    index: u32,
    /// Size of the reassembled payload, so a receiver can reject it before buffering.
    total_len: u32,
}

/// Payload of a fragment message: the [`FragmentHeader`] in CBOR followed directly by the raw
/// data, so the data is not re-encoded.
struct FragmentFrame<'a> {
    header: FragmentHeader,
    data: &'a [u8],
}

impl<'a> FragmentFrame<'a> {
    fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(MAX_HEADER_LEN + self.data.len());
        ciborium::into_writer(&self.header, &mut payload)
            .expect("Ciborium serialization should not fail");
        payload.extend_from_slice(self.data);
        payload
    }

    fn decode(payload: &'a [u8]) -> Option<Self> {
        let mut data = payload;
        let header = ciborium::from_reader(&mut data).ok()?;
        Some(Self { header, data })
    }
}

/// Topic of the message a fragment belongs to, which may itself have no topic.
type OriginalTopic = Option<String>;

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::{
        endpoint::{Endpoint, HostId, Source},
        message::{IncomingMessage, OutgoingMessage},
    };

    /// Crypto provider message limit used by tests that call [`Fragments::split`] directly.
    pub(crate) const MAX_LEN: usize = 64 * 1024;
    pub(crate) const FRAGMENT_LEN: usize = MAX_LEN - MAX_HEADER_LEN;

    pub(crate) fn large_payload(len: usize, seed: u8) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8 ^ seed).collect()
    }

    pub(crate) fn foreground_source(id: i32) -> Source {
        Source::BrowserForeground { id }
    }

    pub(crate) fn web_source(tab_id: i32) -> Source {
        Source::Web {
            tab_id,
            document_id: "doc".to_owned(),
            origin: "https://example.com".to_owned(),
        }
    }

    pub(crate) fn outgoing(payload: Vec<u8>, topic: &str) -> OutgoingMessage {
        OutgoingMessage {
            payload,
            destination: Endpoint::BrowserBackground { id: HostId::Own },
            topic: Some(topic.to_owned()),
        }
    }

    pub(crate) fn incoming(message: OutgoingMessage, source: Source) -> IncomingMessage {
        IncomingMessage {
            payload: message.payload,
            destination: message.destination,
            source,
            topic: message.topic,
        }
    }

    /// Builds a fragment of a message on topic `bulk` that carries 16 bytes of data.
    pub(crate) fn crafted(
        source: Source,
        message_id: u64,
        index: u32,
        total_len: usize,
    ) -> IncomingMessage {
        let payload = FragmentFrame {
            header: FragmentHeader {
                message_id,
                index,
                total_len: total_len as u32,
            },
            data: &[0; 16],
        }
        .encode();
        incoming(
            outgoing(payload, &Fragments::fragment_topic(Some("bulk"))),
            source,
        )
    }

    pub(crate) fn split_all(
        message: OutgoingMessage,
        max_payload_len: usize,
    ) -> Vec<OutgoingMessage> {
        Fragments::split(message, max_payload_len)
            .unwrap()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{test_support::*, *};

    #[test]
    fn fragment_topic_round_trips_and_other_topics_pass_through() {
        for topic in [None, Some(""), Some("bulk"), Some("a/b")] {
            assert_eq!(
                Reassembler::original_topic(Some(&Fragments::fragment_topic(topic))),
                Some(topic.map(str::to_owned))
            );
        }
        for topic in [
            None,
            Some("bulk"),
            Some("IpcFragments"),
            Some("IpcFragment-x"),
        ] {
            assert_eq!(Reassembler::original_topic(topic), None);
        }
    }

    #[test]
    fn largest_header_fits_and_decodes_up_to_its_data() {
        let header = || FragmentHeader {
            message_id: u64::MAX,
            index: u32::MAX,
            total_len: u32::MAX,
        };
        let empty = FragmentFrame {
            header: header(),
            data: &[],
        };
        assert!(empty.encode().len() <= MAX_HEADER_LEN);

        let data = large_payload(FRAGMENT_LEN, 0);
        let payload = FragmentFrame {
            header: header(),
            data: &data,
        }
        .encode();
        assert!(payload.len() <= MAX_LEN);
        let decoded = FragmentFrame::decode(&payload).unwrap();
        assert_eq!(decoded.header.message_id, u64::MAX);
        assert_eq!(decoded.data, data);
    }
}
