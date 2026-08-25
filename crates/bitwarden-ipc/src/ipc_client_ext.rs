use bitwarden_threading::cancellation_token::CancellationToken;
use serde::{Serialize, de::DeserializeOwned};

use crate::{
    RpcHandler,
    endpoint::Endpoint,
    error::{RequestError, SubscribeError},
    ipc_client::IpcClientTypedSubscription,
    ipc_client_trait::IpcClient,
    message::{OutgoingMessage, PayloadTypeName, TypedOutgoingMessage},
    rpc::{
        error::RpcError,
        request::RpcRequest,
        request_message::{RPC_REQUEST_PAYLOAD_TYPE_NAME, RpcRequestMessage},
        response_message::IncomingRpcResponseMessage,
    },
    serde_utils,
};

/// Extension trait providing generic convenience methods on any [`IpcClient`].
///
/// This trait is automatically implemented for all types that implement [`IpcClient`],
/// including `dyn IpcClient`. It provides typed subscriptions, handler registration,
/// and RPC request functionality with full static type safety.
pub trait IpcClientExt: IpcClient {
    /// Register a new RPC handler for processing incoming RPC requests.
    /// The handler will be executed by the IPC client when an RPC request is received and
    /// the response will be sent back over IPC.
    fn register_rpc_handler<H>(&self, handler: H) -> impl std::future::Future<Output = ()> + Send
    where
        H: RpcHandler + Send + Sync + 'static,
    {
        async move {
            self.register_rpc_handler_erased(H::Request::NAME, Box::new(handler))
                .await;
        }
    }

    /// Send a message with a payload of any serializable type to the specified destination.
    fn send_typed<Payload>(
        &self,
        payload: Payload,
        destination: Endpoint,
    ) -> impl std::future::Future<Output = Result<(), RequestError>> + Send
    where
        Payload: Serialize + PayloadTypeName + Send,
    {
        async move {
            let message = TypedOutgoingMessage {
                payload,
                destination,
            }
            .try_into()
            .map_err(|e: serde_utils::DeserializeError| {
                RequestError::Rpc(RpcError::RequestSerialization(e.to_string()))
            })?;

            self.send(message).await.map_err(RequestError::from)
        }
    }

    /// Create a subscription to receive messages that can be deserialized into the provided
    /// payload type.
    fn subscribe_typed<Payload>(
        &self,
    ) -> impl std::future::Future<
        Output = Result<IpcClientTypedSubscription<Payload>, SubscribeError>,
    > + Send
    where
        Payload: DeserializeOwned + PayloadTypeName,
    {
        async move {
            Ok(IpcClientTypedSubscription::new(
                self.subscribe(Some(Payload::PAYLOAD_TYPE_NAME.to_owned()))
                    .await?,
            ))
        }
    }

    /// Send a request to the specified destination and wait for a response.
    /// The destination must have a registered RPC handler for the request type, otherwise
    /// an error will be returned by the remote endpoint.
    fn request<Request>(
        &self,
        request: Request,
        destination: Endpoint,
        cancellation_token: Option<CancellationToken>,
    ) -> impl std::future::Future<Output = Result<Request::Response, RequestError>> + Send
    where
        Request: RpcRequest + Send,
        Request::Response: Send,
    {
        async move {
            let request_payload = RpcRequestMessage::new(request);

            // Each request gets its own response topic, subscribed to before sending. The handler
            // publishes its reply there, so this subscription receives exactly one message: the
            // response to this request. A deserialization failure is therefore unambiguously a
            // malformed response to this request.
            let mut response_subscription = self
                .subscribe(Some(request_payload.response_topic.clone()))
                .await?;

            // Requests are dispatched by a single fixed topic that the receiver matches on to route
            // them to the handler registry.
            let payload = serde_utils::to_vec(&request_payload)
                .map_err(|e| RequestError::Rpc(RpcError::RequestSerialization(e.to_string())))?;
            let message = OutgoingMessage {
                payload,
                destination,
                topic: Some(RPC_REQUEST_PAYLOAD_TYPE_NAME.to_owned()),
            };

            self.send(message).await.map_err(RequestError::from)?;

            let received = response_subscription
                .receive(cancellation_token)
                .await
                .map_err(|e| RequestError::Receive(e.into()))?;

            let response: IncomingRpcResponseMessage<Request::Response> =
                serde_utils::from_slice(&received.payload).map_err(|e| {
                    RequestError::Rpc(RpcError::ResponseDeserialization(e.to_string()))
                })?;

            Ok(response.result?)
        }
    }
}

/// Blanket implementation: every [`IpcClient`] gets the extension methods for free.
impl<T: IpcClient + ?Sized> IpcClientExt for T {}
