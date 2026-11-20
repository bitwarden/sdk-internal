#![allow(clippy::print_stdout)]

//! Plays the app's side of the web connector for the WASM e2e tests, which drive the responder
//! through `@bitwarden/sdk-internal` and use this process as the app. It reads one command per line
//! on stdin and writes one reply per line on stdout:
//!
//! - `start <connector URL> <base64url request>` → `<request URL>`
//! - `decrypt <callback URL>` → `ok <base64url response>` or `error <reason>`
//!
//! Pending requests are kept by their state, and dropped once their response is decrypted. Requests
//! are for [`Connector::WebAuthnAssertion`], the only connector.
//!
//! Build with: `cargo build --example initiator_peer -p bitwarden-web-connector`

use std::{
    collections::HashMap,
    io::{BufRead, Write},
};

use bitwarden_encoding::B64Url;
use bitwarden_web_connector::{Connector, PendingInitiator, State};
use url::Url;

fn main() {
    let mut pending: HashMap<State, PendingInitiator> = HashMap::new();
    let mut stdout = std::io::stdout().lock();
    for line in std::io::stdin().lock().lines() {
        let line = line.expect("stdin is readable");
        let reply = match line.split(' ').collect::<Vec<_>>().as_slice() {
            ["start", connector_url, request] => start(&mut pending, connector_url, request),
            ["decrypt", callback_url] => decrypt(&mut pending, callback_url),
            _ => format!("error unknown command: {line}"),
        };
        writeln!(stdout, "{reply}").expect("stdout is writable");
        stdout.flush().expect("stdout is writable");
    }
}

fn start(
    pending: &mut HashMap<State, PendingInitiator>,
    connector_url: &str,
    request: &str,
) -> String {
    let connector_url = Url::parse(connector_url).expect("connector URL is valid");
    let request = B64Url::try_from(request).expect("request is base64url");
    let (initiator, state, request_url) = PendingInitiator::start(
        Connector::WebAuthnAssertion,
        &connector_url,
        request.as_bytes(),
    )
    .expect("request is small enough");
    pending.insert(state, initiator);
    request_url.to_string()
}

fn decrypt(pending: &mut HashMap<State, PendingInitiator>, callback_url: &str) -> String {
    let Ok(callback_url) = Url::parse(callback_url) else {
        return "error invalid callback URL".to_owned();
    };
    let Ok(state) = State::from_callback(&callback_url) else {
        return "error callback has no state".to_owned();
    };
    let Some(initiator) = pending.get_mut(&state) else {
        return "error no pending request for this state".to_owned();
    };
    match initiator.decrypt_response(&callback_url) {
        Ok(response) => {
            pending.remove(&state);
            format!("ok {}", B64Url::from(response))
        }
        Err(e) => format!("error {e}"),
    }
}
