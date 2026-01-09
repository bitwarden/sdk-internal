# bitwarden-sync

Centralized sync system for the Bitwarden SDK with a hookable event interface.

## Overview

This crate provides sync functionality with an extensible event system that allows other crates and
applications to respond to sync operations. It follows the observer pattern with async support.

## Architecture

### Core Components

- **SyncClient**: Main client for performing sync operations
- **SyncEventHandler**: Trait for implementing custom sync handlers
- **SyncEventRegistry**: Manages handler registration and event dispatch

### Event System

Handlers implement the `SyncEventHandler` trait which provides a single lifecycle hook:

- `on_sync_complete()` - Called after successful sync with raw API response data

Handlers are executed sequentially in registration order. If any handler returns an error, execution
stops immediately and the error is propagated.

#### Transactional Semantics

**Important:** The event system does NOT provide transactional guarantees across handlers or within
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

    // Register handlers
    sync_client.register_handler(Arc::new(FolderSyncHandler::new(client.clone())));

    let request = SyncRequest {
        exclude_subdomains: Some(false),
    };

    // Sync will now persist folders automatically
    let response = sync_client.sync(request).await?;
    Ok(())
}
```
