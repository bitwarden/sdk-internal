# bitwarden-sync

Centralized sync system for the Bitwarden SDK with a hookable handler interface.

## Overview

This crate provides sync functionality with an extensible handler system that allows other crates
and applications to respond to sync operations. It follows the observer pattern with async support.

## Architecture

### Core Components

- **SyncClient**: Main client for performing sync operations
- **SyncHandler**: Trait for implementing custom sync handlers
- **SyncErrorHandler**: Trait for receiving error notifications from sync operations

### Sync Handlers

Sync handlers implement the `SyncHandler` trait which provides two lifecycle hooks:

- `on_sync(response)` - Called after a successful sync with the raw API response data
- `on_sync_complete()` - Called after all handlers have finished `on_sync`, for post-processing
  (default implementation is a no-op)

Both phases execute handlers sequentially in registration order. If any handler returns an error,
execution stops immediately and the error is propagated.

### Error Handlers

Error handlers implement the `SyncErrorHandler` trait:

- `on_error(error)` - Called when a sync operation fails (API error or handler error)

All error handlers are always called sequentially in registration order. Error handlers are called
while the sync lock is still held, so implementations should avoid long-running operations.

#### Transactional Semantics

**Important:** The system does NOT provide transactional guarantees across handlers or within
individual handler operations:

- If a handler fails mid-execution, partial changes persist in storage
- No automatic rollback occurs on handler failure
- Each handler is responsible for its own consistency and error recovery
- Handlers should be idempotent to handle retry scenarios

## Usage

```rust,ignore
use std::sync::Arc;
use bitwarden_sync::{SyncClientExt, SyncRequest};
use bitwarden_vault::FolderSyncHandler;
use bitwarden_core::Client;

async fn example(client: Client) -> Result<(), Box<dyn std::error::Error>> {
    let sync_client = client.sync();

    // Register sync handlers
    sync_client.register_sync_handler(Arc::new(FolderSyncHandler::new(client.clone())));

    let request = SyncRequest {
        exclude_subdomains: Some(false),
    };

    // Sync will now persist folders automatically
    let response = sync_client.sync(request).await?;
    Ok(())
}
```
