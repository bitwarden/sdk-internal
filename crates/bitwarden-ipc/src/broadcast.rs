use serde::{Deserialize, Serialize};

use crate::{
    endpoint::{Endpoint, HostId},
    error::SendError,
};

/// A group of endpoints that a message sent with
/// [`IpcClient::broadcast`](crate::IpcClient::broadcast) is delivered to.
///
/// The platform resolves a group into its current members at send time (see
/// [`CommunicationBackend::resolve`](crate::traits::CommunicationBackend::resolve)). Each member
/// receives its own encrypted message over its own session, so a broadcast never weakens the
/// per-peer guarantees of a unicast send.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[bitwarden_ffi::wasm_record]
pub enum BroadcastGroup {
    /// Every [`BrowserForeground`](Endpoint::BrowserForeground) endpoint (popup, sidebar, or
    /// extension page) that the platform currently knows about.
    AllBrowserForeground,
    /// Every [`BrowserBackground`](Endpoint::BrowserBackground) endpoint addressed by a specific
    /// [`HostId::Id`] that the platform currently knows about (e.g. every
    /// browser extension connected to the desktop app over native messaging).
    AllBrowserBackground,
}

impl BroadcastGroup {
    /// Whether `endpoint` can be a member of this group. The IPC client uses this to reject a
    /// platform resolution that names an endpoint outside the group.
    pub(crate) fn contains(&self, endpoint: &Endpoint) -> bool {
        match self {
            BroadcastGroup::AllBrowserForeground => {
                matches!(endpoint, Endpoint::BrowserForeground { .. })
            }
            // `HostId::Own` is relational and only meaningful to the sender's own background, so
            // it never names a distinct member of a group.
            BroadcastGroup::AllBrowserBackground => {
                matches!(endpoint, Endpoint::BrowserBackground { id: HostId::Id(_) })
            }
        }
    }
}

/// The outcome of delivering a broadcast message to one member of a [`BroadcastGroup`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointSendResult {
    /// The endpoint the message was sent to.
    pub endpoint: Endpoint,
    /// The result of the send to this endpoint. [`SendError::Unreachable`] is an expected outcome
    /// for a broadcast, e.g. when a popup closed between resolution and delivery.
    pub result: Result<(), SendError>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_browser_foreground_contains_only_browser_foreground_endpoints() {
        let group = BroadcastGroup::AllBrowserForeground;

        assert!(group.contains(&Endpoint::BrowserForeground { id: 1 }));
        assert!(!group.contains(&Endpoint::BrowserBackground { id: HostId::Own }));
        assert!(!group.contains(&Endpoint::Web {
            tab_id: 1,
            document_id: "doc".to_string(),
        }));
        assert!(!group.contains(&Endpoint::DesktopMain));
    }

    #[test]
    fn all_browser_background_contains_only_specific_browser_background_endpoints() {
        let group = BroadcastGroup::AllBrowserBackground;

        assert!(group.contains(&Endpoint::BrowserBackground { id: HostId::Id(7) }));
        assert!(!group.contains(&Endpoint::BrowserBackground { id: HostId::Own }));
        assert!(!group.contains(&Endpoint::BrowserForeground { id: 1 }));
        assert!(!group.contains(&Endpoint::DesktopMain));
    }
}
