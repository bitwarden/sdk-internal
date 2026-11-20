#![doc = include_str!("../README.md")]

use std::{fmt, str::FromStr};

use bitwarden_encoding::B64Url;
use bitwarden_error::bitwarden_error;
use rand::RngExt;
use url::{Url, form_urlencoded};

#[cfg(feature = "wasm")]
pub mod wasm;

const PATTERN: &str = "Noise_NN_P256_AESGCM_SHA256";
const PROLOGUE_LABEL: &[u8] = b"bitwarden-web-connector";
const STATE_LEN: usize = 32;
/// Length of an uncompressed P-256 public key.
const DH_LEN: usize = 65;
const TAG_LEN: usize = 16;
const MAX_MESSAGE_LEN: usize = 65535;

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, thiserror::Error)]
pub enum WebConnectorError {
    #[error("Missing or malformed parameter: {0}")]
    MalformedParameter(&'static str),
    #[error("Payload is too large")]
    PayloadTooLarge,
    #[error("The callback does not belong to this request")]
    StateMismatch,
    #[error("Handshake failed")]
    Handshake,
}

/// The flow a request belongs to.
///
/// Used for domain separation, so that a response produced for one
/// connector can't be accepted by a pending request of another.
#[bitwarden_ffi::wasm_object]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Connector {
    /// WebAuthn assertion in the browser, e.g. for login with passkey.
    WebAuthnAssertion,
}

impl Connector {
    fn id(self) -> &'static str {
        match self {
            Self::WebAuthnAssertion => "webauthn-assertion/v1",
        }
    }

    fn callback_path(self) -> &'static str {
        match self {
            Self::WebAuthnAssertion => "webauthn-callback",
        }
    }
}

/// Random value identifying a pending request, like OAuth2 `state`. The initiator uses it to look
/// up the [PendingInitiator] when the callback returns.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct State([u8; STATE_LEN]);

impl State {
    fn generate() -> Self {
        let mut bytes = [0u8; STATE_LEN];
        bitwarden_random::rng().fill(&mut bytes);
        Self(bytes)
    }

    /// Reads the state from a callback URL, to look up the pending request.
    pub fn from_callback(callback: &Url) -> Result<Self, WebConnectorError> {
        param(callback_params(callback), "state")?.parse()
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        B64Url::from(self.0.as_slice()).fmt(f)
    }
}

impl fmt::Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "State({self})")
    }
}

impl FromStr for State {
    type Err = WebConnectorError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes =
            B64Url::try_from(s).map_err(|_| WebConnectorError::MalformedParameter("state"))?;
        bytes
            .as_bytes()
            .try_into()
            .map(Self)
            .map_err(|_| WebConnectorError::MalformedParameter("state"))
    }
}

/// Request held by the initiator (the app) until the callback arrives.
pub struct PendingInitiator {
    state: State,
    handshake: snow::HandshakeState,
}

impl PendingInitiator {
    /// Starts a request.
    ///
    /// Returns the pending request, its [State] for lookup, and the URL to open
    /// in the browser. `request` is sent in plaintext, but it is authenticated: if it is modified,
    /// decrypting the response fails.
    pub fn start(
        connector: Connector,
        connector_url: &Url,
        request: &[u8],
    ) -> Result<(Self, State, Url), WebConnectorError> {
        if request.len() > MAX_MESSAGE_LEN - DH_LEN - TAG_LEN {
            return Err(WebConnectorError::PayloadTooLarge);
        }
        let state = State::generate();
        let mut handshake = handshake_builder(&prologue(connector, &state))
            .build_initiator()
            .map_err(|_| WebConnectorError::Handshake)?;
        // snow reserves room for a tag even though the first message payload is unencrypted.
        let mut message = vec![0u8; DH_LEN + request.len() + TAG_LEN];
        let len = handshake
            .write_message(request, &mut message)
            .map_err(|_| WebConnectorError::Handshake)?;
        message.truncate(len);

        let mut url = connector_url.clone();
        url.set_fragment(Some(
            &form_urlencoded::Serializer::new(String::new())
                .append_pair("state", &state.to_string())
                .append_pair("request", &B64Url::from(message).to_string())
                .finish(),
        ));
        Ok((
            Self {
                state: state.clone(),
                handshake,
            },
            state,
            url,
        ))
    }

    /// Decrypts the response from the callback URL.
    ///
    /// A failure leaves the request pending, so a forged callback can't cancel it. A request can
    /// only be completed once; drop it on success, or when it expires.
    pub fn decrypt_response(&mut self, callback: &Url) -> Result<Vec<u8>, WebConnectorError> {
        let params = callback_params(callback);
        if param(params, "state")?.parse::<State>()? != self.state {
            return Err(WebConnectorError::StateMismatch);
        }
        let message = b64_param(params, "response")?;
        let mut response = vec![0u8; message.len()];
        let len = self
            .handshake
            .read_message(&message, &mut response)
            .map_err(|_| WebConnectorError::Handshake)?;
        response.truncate(len);
        Ok(response)
    }
}

/// Request received by the responder (the web page), held while it produces the response.
pub struct PendingResponder {
    connector: Connector,
    state: State,
    handshake: snow::HandshakeState,
}

impl PendingResponder {
    /// Reads a request from the URL fragment of the connector page. Returns the pending request
    /// and the initiator's request parameters.
    pub fn read_request(
        connector: Connector,
        fragment: &str,
    ) -> Result<(Self, Vec<u8>), WebConnectorError> {
        let fragment = fragment.strip_prefix('#').unwrap_or(fragment);
        let state: State = param(fragment, "state")?.parse()?;
        let message = b64_param(fragment, "request")?;

        let mut handshake = handshake_builder(&prologue(connector, &state))
            .build_responder()
            .map_err(|_| WebConnectorError::Handshake)?;
        let mut request = vec![0u8; message.len()];
        let len = handshake
            .read_message(&message, &mut request)
            .map_err(|_| WebConnectorError::MalformedParameter("request"))?;
        request.truncate(len);
        Ok((
            Self {
                connector,
                state,
                handshake,
            },
            request,
        ))
    }

    /// Encrypts the response and returns the callback URL to navigate to. Fails if the
    /// initiator's public key is not a valid P-256 point.
    pub fn encrypt_response(mut self, response: &[u8]) -> Result<Url, WebConnectorError> {
        if response.len() > MAX_MESSAGE_LEN - DH_LEN - TAG_LEN {
            return Err(WebConnectorError::PayloadTooLarge);
        }
        let mut message = vec![0u8; DH_LEN + response.len() + TAG_LEN];
        let len = self
            .handshake
            .write_message(response, &mut message)
            .map_err(|_| WebConnectorError::Handshake)?;
        message.truncate(len);

        let params = form_urlencoded::Serializer::new(String::new())
            .append_pair("state", &self.state.to_string())
            .append_pair("response", &B64Url::from(message).to_string())
            .finish();
        Ok(callback_url(self.connector, &params))
    }
}

/// The callback URL is derived from the [Connector] so that the server/browser, not a potential
/// local attacker, stays in control of where the responses can be sent.
fn callback_url(connector: Connector, params: &str) -> Url {
    Url::parse(&format!(
        "bitwarden://{}#{params}",
        connector.callback_path()
    ))
    .expect("callback URL is valid")
}

/// Binds the handshake to the connector and the state. Each field is length-prefixed so that
/// different field splits can't produce the same prologue.
fn prologue(connector: Connector, state: &State) -> Vec<u8> {
    let mut prologue = PROLOGUE_LABEL.to_vec();
    for field in [connector.id().as_bytes(), &state.0] {
        let len = u16::try_from(field.len()).expect("prologue fields are short");
        prologue.extend_from_slice(&len.to_be_bytes());
        prologue.extend_from_slice(field);
    }
    prologue
}

fn handshake_builder(prologue: &[u8]) -> snow::Builder<'_> {
    snow::Builder::with_resolver(
        PATTERN.parse().expect("pattern is valid"),
        Box::new(bitwarden_random::SdkCryptoResolver),
    )
    .prologue(prologue)
    .expect("prologue is only set once")
}

fn callback_params(callback: &Url) -> &str {
    callback.fragment().unwrap_or_default()
}

fn param(params: &str, name: &'static str) -> Result<String, WebConnectorError> {
    form_urlencoded::parse(params.as_bytes())
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
        .ok_or(WebConnectorError::MalformedParameter(name))
}

fn b64_param(params: &str, name: &'static str) -> Result<Vec<u8>, WebConnectorError> {
    B64Url::try_from(param(params, name)?)
        .map(B64Url::into_bytes)
        .map_err(|_| WebConnectorError::MalformedParameter(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONNECTOR: Connector = Connector::WebAuthnAssertion;

    fn connector_url() -> Url {
        Url::parse("https://vault.bitwarden.com/webauthn-connector.html").unwrap()
    }

    fn start() -> (PendingInitiator, State, Url) {
        PendingInitiator::start(CONNECTOR, &connector_url(), b"challenge").unwrap()
    }

    fn respond(request_url: &Url, response: &[u8]) -> Url {
        let (responder, request) =
            PendingResponder::read_request(CONNECTOR, request_url.fragment().unwrap()).unwrap();
        assert_eq!(request, b"challenge");
        responder.encrypt_response(response).unwrap()
    }

    #[test]
    fn round_trip() {
        let (mut initiator, state, request_url) = start();
        let callback = respond(&request_url, b"assertion");

        assert!(
            callback
                .as_str()
                .starts_with("bitwarden://webauthn-callback#")
        );
        assert_eq!(State::from_callback(&callback).unwrap(), state);
        assert_eq!(initiator.decrypt_response(&callback).unwrap(), b"assertion");
    }

    #[test]
    fn rejects_mismatched_state() {
        let (mut initiator, _, _) = start();
        let (_, _, other_request_url) = start();
        let callback = respond(&other_request_url, b"assertion");

        assert!(matches!(
            initiator.decrypt_response(&callback),
            Err(WebConnectorError::StateMismatch)
        ));
    }

    #[test]
    fn tampered_response_leaves_request_pending() {
        let (mut initiator, state, request_url) = start();
        let callback = respond(&request_url, b"assertion");

        let mut message = b64_param(callback.fragment().unwrap(), "response").unwrap();
        *message.last_mut().unwrap() ^= 1;
        let tampered = callback_url(
            CONNECTOR,
            &form_urlencoded::Serializer::new(String::new())
                .append_pair("state", &state.to_string())
                .append_pair("response", &B64Url::from(message).to_string())
                .finish(),
        );

        assert!(matches!(
            initiator.decrypt_response(&tampered),
            Err(WebConnectorError::Handshake)
        ));
        assert_eq!(initiator.decrypt_response(&callback).unwrap(), b"assertion");
    }

    #[test]
    fn completes_only_once() {
        let (mut initiator, _, request_url) = start();
        let callback = respond(&request_url, b"assertion");

        initiator.decrypt_response(&callback).unwrap();
        assert!(initiator.decrypt_response(&callback).is_err());
    }

    #[test]
    fn rejects_invalid_public_key() {
        let (_, state, _) = start();
        let fragment = form_urlencoded::Serializer::new(String::new())
            .append_pair("state", &state.to_string())
            .append_pair("request", &B64Url::from(vec![4u8; DH_LEN]).to_string())
            .finish();

        // The point is only validated when the DH is computed.
        let (responder, _) = PendingResponder::read_request(CONNECTOR, &fragment).unwrap();
        assert!(matches!(
            responder.encrypt_response(b"assertion"),
            Err(WebConnectorError::Handshake)
        ));
    }
}
