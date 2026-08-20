//! The client types the SDK's leader discovery understands.

use bitwarden_ipc::{Endpoint, HostId, Source};

/// The client types the SDK's leader discovery understands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClientType {
    Web,
    Browser,
    Cli,
    Desktop,
}

impl ClientType {
    /// The endpoint this device is addressed at.
    pub(super) fn endpoint(&self, instance: i32, name: &str) -> Endpoint {
        match self {
            // `Endpoint` has no CLI variant, so `DesktopMain` stands in for one.
            ClientType::Cli => Endpoint::DesktopMain,
            ClientType::Desktop => Endpoint::DesktopRenderer,
            ClientType::Browser => Endpoint::BrowserBackground {
                id: HostId::Id(instance),
            },
            ClientType::Web => Endpoint::Web {
                tab_id: instance,
                document_id: format!("{name}-document"),
            },
        }
    }

    /// The source stamped onto this device's outgoing messages. Only a web source carries an
    /// origin, which is what its leader validates.
    pub(super) fn source(&self, instance: i32, name: &str, vault_url: Option<&str>) -> Source {
        match self {
            ClientType::Cli => Source::DesktopMain,
            ClientType::Desktop => Source::DesktopRenderer,
            ClientType::Browser => Source::BrowserBackground {
                id: HostId::Id(instance),
            },
            ClientType::Web => Source::Web {
                tab_id: instance,
                document_id: format!("{name}-document"),
                origin: vault_url.unwrap_or_default().to_owned(),
            },
        }
    }

    /// Whether this client type sits below another, and so has to be declared with a leader.
    pub(super) fn has_leader(&self) -> bool {
        !matches!(self, ClientType::Desktop)
    }

    /// Whether this client type discovers its leader at an endpoint like `leader`.
    pub(super) fn can_follow(&self, leader: &Endpoint) -> bool {
        match self {
            ClientType::Web => matches!(leader, Endpoint::BrowserBackground { .. }),
            ClientType::Browser | ClientType::Cli => matches!(leader, Endpoint::DesktopRenderer),
            ClientType::Desktop => false,
        }
    }
}
