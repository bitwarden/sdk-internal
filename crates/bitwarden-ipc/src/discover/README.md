# Discover

A built-in RPC request/response pair for client discovery and health checking over IPC.

## Purpose

The discover module provides a simple "ping" mechanism that allows one IPC endpoint to check whether
another endpoint is alive and reachable. The responding endpoint includes its version string, which
can be used for compatibility checks.

## Types

- **`DiscoverRequest`**: An empty RPC request that acts as a ping. Implements `RpcRequest` with
  `NAME = "DiscoverRequest"`.
- **`DiscoverResponse`**: Contains a `version` string identifying the responding client.
- **`DiscoverHandler`**: A pre-built `RpcHandler` that responds to `DiscoverRequest` with a fixed
  `DiscoverResponse`. Register it on an `IpcClient` to make that client discoverable.

## Usage

### Responding to discover requests

Register the handler so the client responds to incoming discover requests:

```rust,ignore
let handler = DiscoverHandler::new(DiscoverResponse {
    version: "1.0.0".to_string(),
});
ipc_client.register_rpc_handler(handler).await;
```

### Sending a discover request

Send a discover request to a specific endpoint:

```rust,ignore
let response = ipc_client
    .request::<DiscoverRequest>(
        DiscoverRequest,
        destination_endpoint,
        None, // optional cancellation token
    )
    .await?;
println!("Remote version: {}", response.version);
```

### WASM

In WASM contexts, two functions are exported:

- `ipcRegisterDiscoverHandler(client, response)`: registers the handler
- `ipcRequestDiscover(client, destination, abortSignal?)`: sends a discover request
