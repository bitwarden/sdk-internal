//! WASM bindings for the responder, used by the web vault's connector pages through
//! `@bitwarden/sdk-internal`.

use crate::{Connector, PendingResponder, WebConnectorError};

/// A request read by a connector page, held while the page produces the response.
#[bitwarden_ffi::wasm_object]
pub struct WebConnectorResponder {
    inner: PendingResponder,
    request: Vec<u8>,
}

#[bitwarden_ffi::wasm_export]
impl WebConnectorResponder {
    /// Reads a request from the connector page's URL fragment, with or without the leading `#`.
    pub fn read_request(
        connector: Connector,
        fragment: &str,
    ) -> Result<WebConnectorResponder, WebConnectorError> {
        let (inner, request) = PendingResponder::read_request(connector, fragment)?;
        Ok(Self { inner, request })
    }

    /// The initiator's request parameters.
    pub fn request(&self) -> Vec<u8> {
        self.request.clone()
    }

    /// Encrypts the response and returns the callback URL to navigate to. The responder can't be
    /// used afterwards.
    pub fn encrypt_response(self, response: Vec<u8>) -> Result<String, WebConnectorError> {
        self.inner
            .encrypt_response(&response)
            .map(|url| url.to_string())
    }
}
