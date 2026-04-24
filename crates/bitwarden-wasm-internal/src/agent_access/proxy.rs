//! JS-backed ProxyClient implementation for WASM.
//!
//! Delegates all proxy communication to a JavaScript object, following the
//! `JsTokenProvider` pattern from the SDK.

use std::rc::Rc;

use ap_client::{ClientError, IdentityFingerprint, ProxyClient, RendezvousCode};
use ap_proxy_client::IncomingMessage;
use ap_proxy_protocol::{Identity, IdentityKeyPair};
use async_trait::async_trait;
use bitwarden_threading::ThreadBoundRunner;
use tokio::sync::mpsc;
use wasm_bindgen::{JsValue, prelude::*};

#[wasm_bindgen(typescript_custom_section)]
const PROXY_TS_TYPE: &'static str = r#"
export interface ProxyClient {
    connect(onMessage: (msg: any) => void): Promise<void>;
    request_rendezvous(): Promise<void>;
    request_identity(code: string): Promise<void>;
    send_to(fingerprint: string, data: Uint8Array): Promise<void>;
    disconnect(): Promise<void>;
}
"#;

#[wasm_bindgen]
extern "C" {
    /// JavaScript-provided proxy client implementation.
    #[wasm_bindgen(js_name = ProxyClient)]
    pub type JsProxyClient;

    #[wasm_bindgen(method, catch)]
    async fn connect(
        this: &JsProxyClient,
        on_message: &Closure<dyn FnMut(JsValue)>,
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch)]
    async fn request_rendezvous(this: &JsProxyClient) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch)]
    async fn request_identity(this: &JsProxyClient, code: String) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch)]
    async fn send_to(
        this: &JsProxyClient,
        fingerprint: String,
        data: Vec<u8>,
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch)]
    async fn disconnect(this: &JsProxyClient) -> Result<JsValue, JsValue>;
}

/// WASM proxy client that delegates to JavaScript.
pub(crate) struct WasmProxyClient {
    runner: ThreadBoundRunner<WasmProxyState>,
}

/// Internal state held by ThreadBoundRunner (must be !Send-compatible via ThreadBoundRunner).
struct WasmProxyState {
    js_client: JsProxyClient,
    /// Stored to prevent the closure from being dropped while JS holds a reference.
    #[allow(dead_code)]
    on_message_closure: Option<Closure<dyn FnMut(JsValue)>>,
}

impl WasmProxyClient {
    pub(crate) fn new(js_client: JsProxyClient) -> Self {
        Self {
            runner: ThreadBoundRunner::new(WasmProxyState {
                js_client,
                on_message_closure: None,
            }),
        }
    }
}

fn js_err(e: JsValue) -> ClientError {
    ClientError::ConnectionFailed(format!("{e:?}"))
}

pub(crate) fn fingerprint_to_hex(fp: &IdentityFingerprint) -> String {
    use std::fmt::Write;
    fp.0.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

pub(crate) fn hex_to_fingerprint(hex_str: &str) -> Result<IdentityFingerprint, String> {
    let bytes = hex_str.as_bytes();
    if bytes.len() != 64 {
        return Err(format!(
            "fingerprint hex must be 64 chars, got {}",
            hex_str.len()
        ));
    }
    let mut arr = [0u8; 32];
    for i in 0..32 {
        let pair = std::str::from_utf8(&bytes[i * 2..i * 2 + 2]).map_err(|e| e.to_string())?;
        arr[i] = u8::from_str_radix(pair, 16).map_err(|e| e.to_string())?;
    }
    Ok(IdentityFingerprint(arr))
}

#[async_trait]
impl ProxyClient for WasmProxyClient {
    async fn connect(
        &mut self,
        _identity: IdentityKeyPair,
    ) -> Result<mpsc::UnboundedReceiver<IncomingMessage>, ClientError> {
        tracing::info!("[Agent Access Proxy] connect() called, creating channel...");
        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();

        tracing::info!("[Agent Access Proxy] dispatching connect via ThreadBoundRunner...");
        self.runner
            .run_in_thread(move |state: Rc<WasmProxyState>| async move {
                tracing::info!(
                    "[Agent Access Proxy] inside ThreadBoundRunner task, creating Closure..."
                );
                // Create a closure that JS calls for each incoming WebSocket message
                let on_message =
                    Closure::wrap(
                        Box::new(move |msg: JsValue| match parse_incoming_message(msg) {
                            Ok(incoming) => {
                                tracing::info!("WasmProxyClient: received incoming message");
                                let _ = incoming_tx.send(incoming);
                            }
                            Err(e) => {
                                tracing::warn!("WasmProxyClient: failed to parse message: {e}");
                            }
                        }) as Box<dyn FnMut(JsValue)>,
                    );

                tracing::info!("[Agent Access Proxy] calling JS connect()...");
                state.js_client.connect(&on_message).await.map_err(js_err)?;
                tracing::info!("[Agent Access Proxy] JS connect() returned successfully");

                // Leak the closure to keep it alive. The JS side holds a reference to it
                // and will call it for each message. It lives as long as the connection.
                on_message.forget();

                Ok::<(), ClientError>(())
            })
            .await
            .expect("Task should not panic")?;

        tracing::info!("[Agent Access Proxy] connect complete");
        Ok(incoming_rx)
    }

    async fn request_rendezvous(&self) -> Result<(), ClientError> {
        self.runner
            .run_in_thread(|state| async move {
                state.js_client.request_rendezvous().await.map_err(js_err)?;
                Ok::<(), ClientError>(())
            })
            .await
            .expect("Task should not panic")
    }

    async fn request_identity(&self, code: RendezvousCode) -> Result<(), ClientError> {
        let code_str = code.as_str().to_string();
        self.runner
            .run_in_thread(move |state| async move {
                state
                    .js_client
                    .request_identity(code_str)
                    .await
                    .map_err(js_err)?;
                Ok::<(), ClientError>(())
            })
            .await
            .expect("Task should not panic")
    }

    async fn send_to(
        &self,
        fingerprint: IdentityFingerprint,
        data: Vec<u8>,
    ) -> Result<(), ClientError> {
        let fp_hex = fingerprint_to_hex(&fingerprint);
        self.runner
            .run_in_thread(move |state| async move {
                state
                    .js_client
                    .send_to(fp_hex, data)
                    .await
                    .map_err(js_err)?;
                Ok::<(), ClientError>(())
            })
            .await
            .expect("Task should not panic")
    }

    async fn disconnect(&mut self) -> Result<(), ClientError> {
        self.runner
            .run_in_thread(|state| async move {
                state.js_client.disconnect().await.map_err(js_err)?;
                Ok::<(), ClientError>(())
            })
            .await
            .expect("Task should not panic")
    }
}

/// Parse an incoming message from JS into the ap-proxy IncomingMessage type.
fn parse_incoming_message(msg: JsValue) -> Result<IncomingMessage, String> {
    let parsed: serde_json::Value =
        tsify::serde_wasm_bindgen::from_value(msg).map_err(|e| e.to_string())?;

    let msg_type = parsed["type"].as_str().unwrap_or("");

    match msg_type {
        "send" => {
            let source_hex = parsed["source"].as_str().unwrap_or("");
            let dest_hex = parsed["destination"].as_str().unwrap_or("");

            let source = hex_to_fingerprint(source_hex)?;
            let destination = hex_to_fingerprint(dest_hex)?;

            // Payload comes as a base64 string from JS
            let payload = if let Some(arr) = parsed["payload"].as_array() {
                arr.iter()
                    .filter_map(|v| v.as_u64().map(|n| n as u8))
                    .collect()
            } else if let Some(b64) = parsed["payload"].as_str() {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .map_err(|e| e.to_string())?
            } else {
                Vec::new()
            };

            Ok(IncomingMessage::Send {
                source,
                destination,
                payload,
            })
        }
        "rendezvous_info" => {
            let code = parsed["code"].as_str().ok_or("missing code")?.to_string();
            Ok(IncomingMessage::RendezvousInfo(
                RendezvousCode::from_string(code),
            ))
        }
        "identity_info" => {
            let fp_hex = parsed["fingerprint"].as_str().unwrap_or("");
            let fingerprint = hex_to_fingerprint(fp_hex)?;
            let identity: Identity =
                serde_json::from_value(parsed["identity"].clone()).map_err(|e| e.to_string())?;
            Ok(IncomingMessage::IdentityInfo {
                fingerprint,
                identity,
            })
        }
        _ => Err(format!("Unknown message type: {msg_type}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- fingerprint_to_hex ---

    #[test]
    fn fingerprint_to_hex_all_zeros() {
        let fp = IdentityFingerprint([0u8; 32]);
        assert_eq!(fingerprint_to_hex(&fp), "0".repeat(64));
    }

    #[test]
    fn fingerprint_to_hex_all_ff() {
        let fp = IdentityFingerprint([0xFF; 32]);
        assert_eq!(fingerprint_to_hex(&fp), "f".repeat(64));
    }

    #[test]
    fn fingerprint_to_hex_known_pattern() {
        let mut arr = [0u8; 32];
        arr[0] = 0xAB;
        arr[1] = 0xCD;
        arr[31] = 0xEF;
        let fp = IdentityFingerprint(arr);
        let hex = fingerprint_to_hex(&fp);
        assert_eq!(hex.len(), 64);
        assert!(hex.starts_with("abcd"));
        assert!(hex.ends_with("ef"));
    }

    // --- hex_to_fingerprint ---

    #[test]
    fn hex_to_fingerprint_roundtrip() {
        let original = IdentityFingerprint([0xAB; 32]);
        let hex = fingerprint_to_hex(&original);
        let restored = hex_to_fingerprint(&hex).unwrap();
        assert_eq!(original.0, restored.0);
    }

    #[test]
    fn hex_to_fingerprint_all_zeros() {
        let hex = "0".repeat(64);
        let fp = hex_to_fingerprint(&hex).unwrap();
        assert_eq!(fp.0, [0u8; 32]);
    }

    #[test]
    fn hex_to_fingerprint_wrong_length_short() {
        let result = hex_to_fingerprint("abcd");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("64 chars"));
    }

    #[test]
    fn hex_to_fingerprint_wrong_length_long() {
        let result = hex_to_fingerprint(&"a".repeat(66));
        assert!(result.is_err());
    }

    #[test]
    fn hex_to_fingerprint_invalid_hex_chars() {
        let mut hex = "0".repeat(64);
        hex.replace_range(0..2, "zz");
        let result = hex_to_fingerprint(&hex);
        assert!(result.is_err());
    }

    #[test]
    fn hex_to_fingerprint_uppercase_works() {
        let hex = "AB".repeat(32);
        let fp = hex_to_fingerprint(&hex).unwrap();
        assert_eq!(fp.0, [0xAB; 32]);
    }

    #[test]
    fn hex_to_fingerprint_mixed_case_works() {
        let hex = "aB".repeat(32);
        let fp = hex_to_fingerprint(&hex).unwrap();
        assert_eq!(fp.0, [0xAB; 32]);
    }
}
