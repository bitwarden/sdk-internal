use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use {tsify::Tsify, wasm_bindgen::prelude::*};

/// Identifies a host endpoint, one that manages connections for other endpoints.
///
/// Host endpoints can be addressed relationally (when the sender has a direct connection
/// and there is only one from their perspective) or by a specific transport-assigned ID
/// (when distinguishing between multiple instances).
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum HostId {
    /// The sender's own instance of this endpoint type. Used when there is exactly one
    /// from the sender's perspective (e.g., a web tab addressing its browser background).
    Own,
    /// A specific instance identified by a transport-assigned numeric value
    /// (e.g., native messaging client ID).
    Id(i32),
}

/// IPC destination/source endpoint for SDK clients.
///
/// Endpoints are categorized by their role in the connection topology:
/// - **Host endpoints** ([`HostId`]): Connection hubs that can be addressed relationally or
///   specifically. ([`BrowserBackground`](Endpoint::BrowserBackground))
/// - **Leaf endpoints**: Addressed by transport-assigned IDs. ([`Web`](Endpoint::Web),
///   [`BrowserForeground`](Endpoint::BrowserForeground))
/// - **Singleton endpoints**: Exactly one instance globally, no ID needed.
///   ([`DesktopMain`](Endpoint::DesktopMain), [`DesktopRenderer`](Endpoint::DesktopRenderer))
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum Endpoint {
    /// A web endpoint identified by a Chrome tab ID (for routing via
    /// `chrome.tabs.sendMessage`) and a document ID (for identity validation).
    /// The document ID invalidates on navigation, allowing the browser background
    /// to reject delivery if the page changed since the message was addressed.
    Web {
        /// Chrome tab ID used for routing messages to the correct tab.
        tab_id: i32,
        /// Document ID (`sender.documentId`) identifying a specific document instance.
        document_id: String,
    },
    /// Browser foreground endpoint (popup, sidebar, or extension page) identified by a
    /// transport-assigned numeric ID.
    BrowserForeground {
        /// Transport-assigned identifier for a browser foreground instance.
        id: i32,
    },
    /// Browser background endpoint (service worker/background context).
    BrowserBackground {
        /// Host identifier for addressing this endpoint.
        id: HostId,
    },
    /// Desktop renderer endpoint (singleton).
    DesktopRenderer,
    /// Desktop main-process endpoint (singleton).
    DesktopMain,
}

/// Describes the source of an incoming IPC message with per-variant metadata.
///
/// `Source` mirrors [`Endpoint`] but carries additional context about the sender
/// that the application layer needs for security decisions (e.g., checking `origin`
/// for web sources). Use [`From<Source> for Endpoint`] to convert a source into an
/// addressable endpoint (dropping the metadata).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum Source {
    /// A web source identified by tab ID and document ID, with the origin of the sending page.
    Web {
        /// Chrome tab ID used for routing messages back to this tab.
        tab_id: i32,
        /// Document ID (`sender.documentId`) identifying the specific document instance.
        document_id: String,
        /// The origin of the web page (e.g., `"https://vault.bitwarden.com"`).
        origin: String,
    },
    /// Browser foreground source (popup, sidebar, or extension page).
    BrowserForeground {
        /// Transport-assigned identifier for the browser foreground instance.
        id: i32,
    },
    /// Browser background source (service worker/background context).
    BrowserBackground {
        /// Host identifier for this endpoint.
        id: HostId,
    },
    /// Desktop renderer source (singleton).
    DesktopRenderer,
    /// Desktop main-process source (singleton).
    DesktopMain,
}

impl Source {
    /// Convert this source into its corresponding [`Endpoint`], dropping any
    /// source-specific metadata (such as `origin`).
    pub fn to_endpoint(&self) -> Endpoint {
        Endpoint::from(self.clone())
    }
}

impl From<Source> for Endpoint {
    fn from(source: Source) -> Self {
        match source {
            Source::Web {
                tab_id,
                document_id,
                ..
            } => Endpoint::Web {
                tab_id,
                document_id,
            },
            Source::BrowserForeground { id } => Endpoint::BrowserForeground { id },
            Source::BrowserBackground { id } => Endpoint::BrowserBackground { id },
            Source::DesktopRenderer => Endpoint::DesktopRenderer,
            Source::DesktopMain => Endpoint::DesktopMain,
        }
    }
}
