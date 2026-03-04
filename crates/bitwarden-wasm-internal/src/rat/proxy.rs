//! JS-backed ProxyClient implementation for WASM.
//!
//! Delegates all proxy communication to a JavaScript object, following the
//! `JsTokenProvider` pattern from the SDK.

use std::rc::Rc;

use async_trait::async_trait;
use bitwarden_threading::ThreadBoundRunner;
use bw_rat_client::{
    Identity, IdentityFingerprint, IncomingMessage, ProxyClient, RemoteClientError, RendevouzCode,
};
use tokio::sync::mpsc;
use wasm_bindgen::{JsValue, prelude::*};

#[wasm_bindgen(typescript_custom_section)]
const RAT_PROXY_TS_TYPE: &'static str = r#"
export interface RatProxyClient {
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
    #[wasm_bindgen(js_name = RatProxyClient)]
    pub type JsRatProxyClient;

    #[wasm_bindgen(method, catch)]
    async fn connect(
        this: &JsRatProxyClient,
        on_message: &Closure<dyn FnMut(JsValue)>,
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch)]
    async fn request_rendezvous(this: &JsRatProxyClient) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch)]
    async fn request_identity(this: &JsRatProxyClient, code: String) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch)]
    async fn send_to(
        this: &JsRatProxyClient,
        fingerprint: String,
        data: Vec<u8>,
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch)]
    async fn disconnect(this: &JsRatProxyClient) -> Result<JsValue, JsValue>;
}

/// WASM proxy client that delegates to JavaScript.
pub(crate) struct WasmProxyClient {
    runner: ThreadBoundRunner<WasmProxyState>,
}

/// Internal state held by ThreadBoundRunner (must be !Send-compatible via ThreadBoundRunner).
struct WasmProxyState {
    js_client: JsRatProxyClient,
    /// Stored to prevent the closure from being dropped while JS holds a reference.
    #[allow(dead_code)]
    on_message_closure: Option<Closure<dyn FnMut(JsValue)>>,
}

impl WasmProxyClient {
    pub(crate) fn new(js_client: JsRatProxyClient) -> Self {
        Self {
            runner: ThreadBoundRunner::new(WasmProxyState {
                js_client,
                on_message_closure: None,
            }),
        }
    }
}

fn js_err(e: JsValue) -> RemoteClientError {
    RemoteClientError::ConnectionFailed(format!("{e:?}"))
}

fn fingerprint_to_hex(fp: &IdentityFingerprint) -> String {
    fp.0.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_to_fingerprint(hex_str: &str) -> Result<IdentityFingerprint, String> {
    if hex_str.len() != 64 {
        return Err(format!(
            "fingerprint hex must be 64 chars, got {}",
            hex_str.len()
        ));
    }
    let mut arr = [0u8; 32];
    for i in 0..32 {
        arr[i] = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(IdentityFingerprint(arr))
}

#[async_trait]
impl ProxyClient for WasmProxyClient {
    async fn connect(
        &mut self,
    ) -> Result<mpsc::UnboundedReceiver<IncomingMessage>, RemoteClientError> {
        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();

        self.runner
            .run_in_thread(move |state: Rc<WasmProxyState>| async move {
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

                state.js_client.connect(&on_message).await.map_err(js_err)?;

                // Leak the closure to keep it alive. The JS side holds a reference to it
                // and will call it for each message. It lives as long as the connection.
                on_message.forget();

                Ok::<(), RemoteClientError>(())
            })
            .await
            .expect("Task should not panic")?;

        Ok(incoming_rx)
    }

    async fn request_rendezvous(&self) -> Result<(), RemoteClientError> {
        self.runner
            .run_in_thread(|state| async move {
                state.js_client.request_rendezvous().await.map_err(js_err)?;
                Ok::<(), RemoteClientError>(())
            })
            .await
            .expect("Task should not panic")
    }

    async fn request_identity(&self, code: RendevouzCode) -> Result<(), RemoteClientError> {
        let code_str = code.as_str().to_string();
        self.runner
            .run_in_thread(move |state| async move {
                state
                    .js_client
                    .request_identity(code_str)
                    .await
                    .map_err(js_err)?;
                Ok::<(), RemoteClientError>(())
            })
            .await
            .expect("Task should not panic")
    }

    async fn send_to(
        &self,
        fingerprint: IdentityFingerprint,
        data: Vec<u8>,
    ) -> Result<(), RemoteClientError> {
        let fp_hex = fingerprint_to_hex(&fingerprint);
        self.runner
            .run_in_thread(move |state| async move {
                state
                    .js_client
                    .send_to(fp_hex, data)
                    .await
                    .map_err(js_err)?;
                Ok::<(), RemoteClientError>(())
            })
            .await
            .expect("Task should not panic")
    }

    async fn disconnect(&mut self) -> Result<(), RemoteClientError> {
        self.runner
            .run_in_thread(|state| async move {
                state.js_client.disconnect().await.map_err(js_err)?;
                Ok::<(), RemoteClientError>(())
            })
            .await
            .expect("Task should not panic")
    }
}

/// Parse an incoming message from JS into the bw-proxy IncomingMessage type.
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
            Ok(IncomingMessage::RendevouzInfo(RendevouzCode::from_string(
                code,
            )))
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
