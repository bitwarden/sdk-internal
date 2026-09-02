//! Hand-rolled, debug-only introspection capabilities that reach past the
//! public API for automated debugging tooling.
//!
//! These are compiled only under the `introspect` feature and must never ship
//! in production. Unlike the derived object-graph crawl (which walks public
//! accessors), each function here is written by hand to read and mutate
//! internal state the public API does not surface, such as the user's stored
//! login method. Access is asynchronous because the state lives behind the
//! async state registry.

use crate::{
    Client,
    client::login_method::{LoginMethod, UserLoginMethod},
};

/// Read the user's current login method: the client id, email, KDF, and (for
/// API-key logins) the client secret. Not exposed by the public API.
///
/// Returns `None` when no user login method is set, for example on a locked or
/// service-account client.
pub async fn debug_get_login_method(client: &Client) -> Option<UserLoginMethod> {
    client.internal.get_login_method().await
}

/// Overwrite the user's current login method. Debug-only: this bypasses the
/// normal login flow and exists to drive a client into a specific state while
/// debugging.
pub async fn debug_set_login_method(client: &Client, method: UserLoginMethod) {
    client
        .internal
        .set_login_method(LoginMethod::User(method))
        .await;
}
