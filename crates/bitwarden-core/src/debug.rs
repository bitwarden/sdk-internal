//! Dev-only debug capabilities.
//!
//! These reach past the public API into internal client state so automated
//! tooling can read and drive things the normal API does not expose. They are
//! compiled only under the `debug-capabilities` feature and must never ship in
//! production. Kept in their own module, deliberately separate from the regular
//! client API.

use crate::{
    Client,
    client::login_method::{LoginMethod, UserLoginMethod},
};

/// Debug capabilities over a user's auth/session state.
///
/// Holds a cheap, `Arc`-backed [`Client`] clone, so it owns everything it needs
/// and nothing borrows across an FFI boundary.
pub struct AuthDebug {
    client: Client,
}

impl AuthDebug {
    /// Wrap the owning client. Built by the debug-tree root, not called directly.
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Read the user's stored login method (client id, email, KDF, and — for
    /// API-key logins — the client secret). `None` on a locked or
    /// service-account client. Bypasses the public API.
    pub async fn login_method(&self) -> Option<UserLoginMethod> {
        self.client.internal.get_login_method().await
    }

    /// Overwrite the user's stored login method. Debug-only: bypasses the normal
    /// login flow to drive a client into a specific state.
    pub async fn set_login_method(&self, method: UserLoginMethod) {
        self.client
            .internal
            .set_login_method(LoginMethod::User(method))
            .await;
    }
}
