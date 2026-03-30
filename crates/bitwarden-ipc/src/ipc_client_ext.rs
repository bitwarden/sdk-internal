use bitwarden_threading::cancellation_token::CancellationToken;
use serde::de::DeserializeOwned;

use crate::{
    RpcHandler,
    endpoint::Endpoint,
    error::{RequestError, SubscribeError},
    ipc_client::IpcClientTypedSubscription,
    ipc_client_trait::IpcClient,
    message::{PayloadTypeName, TypedOutgoingMessage},
    rpc::{
        error::RpcError, request::RpcRequest, request_message::RpcRequestMessage,
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
            let request_id = uuid::Uuid::new_v4().to_string();
            let mut response_subscription = self
                .subscribe_typed::<IncomingRpcResponseMessage<Request::Response>>()
                .await?;

            let request_payload = RpcRequestMessage {
                request,
                request_id: request_id.clone(),
                request_type: Request::NAME.to_owned(),
            };

            let message = TypedOutgoingMessage {
                payload: request_payload,
                destination,
            }
            .try_into()
            .map_err(|e: serde_utils::DeserializeError| {
                RequestError::Rpc(RpcError::RequestSerialization(e.to_string()))
            })?;

            self.send(message)
                .await
                .map_err(|e| RequestError::Send(format!("{e:?}")))?;

            let response = loop {
                let received = response_subscription
                    .receive(cancellation_token.clone())
                    .await
                    .map_err(RequestError::Receive)?;

                if received.payload.request_id == request_id {
                    break received;
                }
            };

            Ok(response.payload.result?)
        }
    }
}

/// Blanket implementation: every [`IpcClient`] gets the extension methods for free.
impl<T: IpcClient + ?Sized> IpcClientExt for T {}
