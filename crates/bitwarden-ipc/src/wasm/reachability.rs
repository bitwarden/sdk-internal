use std::sync::Arc;

use wasm_bindgen::prelude::*;

use crate::{
    endpoint::Endpoint,
    reachability::{ReachabilityHandle, ReachabilityTracker},
};

/// JavaScript wrapper around the reachability tracker. See
/// [`ReachabilityTracker`](crate::ReachabilityTracker).
#[wasm_bindgen(js_name = ReachabilityTracker)]
pub struct JsReachabilityTracker {
    pub(crate) tracker: Arc<ReachabilityTracker>,
}

#[bitwarden_ffi::wasm_export]
#[wasm_bindgen(js_class = ReachabilityTracker)]
impl JsReachabilityTracker {
    /// Begin tracking `endpoint`'s reachability, returning a handle. Hold the handle for as long as
    /// you care about the endpoint; calling `free()` on it (or letting it be garbage-collected)
    /// stops tracking that endpoint.
    #[wasm_only]
    pub fn track(&self, endpoint: Endpoint) -> JsReachabilityHandle {
        JsReachabilityHandle {
            handle: self.tracker.track(endpoint),
        }
    }
}

/// JavaScript wrapper around a reachability handle. See
/// [`ReachabilityHandle`](crate::ReachabilityHandle).
#[wasm_bindgen(js_name = ReachabilityHandle)]
pub struct JsReachabilityHandle {
    handle: ReachabilityHandle,
}

#[bitwarden_ffi::wasm_export]
#[wasm_bindgen(js_class = ReachabilityHandle)]
impl JsReachabilityHandle {
    /// Whether the tracked endpoint is currently reachable.
    #[wasm_only]
    #[wasm_bindgen(js_name = isReachable)]
    pub async fn is_reachable(&self) -> bool {
        self.handle.is_reachable().await
    }
}
