#![allow(clippy::print_stdout)]

//! Walks through one request from the app to a web page and back.
//!
//! In a real flow the two halves run in different processes: the app is the initiator, and the
//! connector page in the browser is the responder (through `WebConnectorResponder` in
//! `@bitwarden/sdk-internal`). Here both run in one process, and the URLs are passed directly
//! instead of going through the browser and the `bitwarden://` scheme handler.
//!
//! Run with: `cargo run --example round_trip -p bitwarden-web-connector`

use std::collections::HashMap;

use bitwarden_web_connector::{Connector, PendingInitiator, PendingResponder, State};
use url::Url;

fn main() {
    // App: start a request and keep it until the callback arrives. The request travels in the URL
    // in plaintext, so it must not contain secrets.
    let connector_url = Url::parse("https://vault.bitwarden.com/webauthn-connector.html")
        .expect("connector URL is valid");
    let (initiator, state, request_url) = PendingInitiator::start(
        Connector::WebAuthnAssertion,
        &connector_url,
        br#"{"challenge":"..."}"#,
    )
    .expect("request is small enough");
    let mut pending: HashMap<State, PendingInitiator> = HashMap::new();
    pending.insert(state, initiator);
    println!("App opens:          {request_url}");

    // Page: read the request from its URL fragment, do the work, and navigate to the callback.
    let (responder, request) = PendingResponder::read_request(
        Connector::WebAuthnAssertion,
        request_url.fragment().expect("request URL has a fragment"),
    )
    .expect("request is well formed");
    println!("Page receives:      {}", String::from_utf8_lossy(&request));
    let callback_url = responder
        .encrypt_response(br#"{"assertion":"..."}"#)
        .expect("response is small enough");
    println!("Page navigates to:  {callback_url}");

    // App: the scheme handler delivers the callback. Look up the pending request by its state,
    // decrypt, and drop the request once it succeeds.
    let state = State::from_callback(&callback_url).expect("callback has a state");
    let mut initiator = pending
        .remove(&state)
        .expect("callback belongs to a pending request");
    let response = initiator
        .decrypt_response(&callback_url)
        .expect("response was produced for this request");
    println!("App decrypts:       {}", String::from_utf8_lossy(&response));
}
