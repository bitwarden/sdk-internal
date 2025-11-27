# bitwarden-ipc

Read any available documentation: [README.md](./README.md) for architecture,
[examples/](./examples/) for usage patterns, and [tests/](./tests/) for integration tests.

## Critical Rules

**RPC types require serialization**: All `RpcRequest` and response types must implement
`Serialize + DeserializeOwned`.

**Subscribe before sending**: Call `subscribe()` before `send()` to prevent race conditions where
messages arrive before subscription.

**Call `start()` first**: Client must be started via `start()` before subscribing or
`SubscribeError::NotStarted` is returned.

**Handler name collisions**: Registering multiple handlers with the same `RpcRequest::NAME` causes
last registration to silently win—no error is raised.
