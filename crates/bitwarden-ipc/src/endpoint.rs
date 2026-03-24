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
/// - **Leaf endpoints** (`i32`): Always addressed by a specific transport-assigned ID.
///   ([`Web`](Endpoint::Web), [`BrowserForeground`](Endpoint::BrowserForeground))
/// - **Singleton endpoints**: Exactly one instance globally, no ID needed.
///   ([`DesktopMain`](Endpoint::DesktopMain), [`DesktopRenderer`](Endpoint::DesktopRenderer))
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum Endpoint {
    /// A web endpoint identified by a transport-assigned numeric ID (e.g., Chrome tab ID).
    Web {
        /// Transport-assigned identifier for a web endpoint instance.
        id: i32,
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
