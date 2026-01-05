# bitwarden-settings

Type-safe settings repository for storing application configuration and state.

## Overview

This crate provides a high-level API for storing and retrieving typed settings using compile-time
type-safe keys, backed by the SDK's repository pattern with SQLite storage.

## Features

- **Type Safety**: Compile-time type-safe keys prevent type mismatches
- **Automatic Serialization**: JSON serialization/deserialization handled automatically
- **Graceful Error Handling**: Deserialization errors are logged but don't propagate
- **SDK Integration**: Built on top of bitwarden-state repository pattern

## Usage

```rust
use bitwarden_settings::{ClientSettingsExt, Key};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct AppConfig {
    theme: String,
    auto_save: bool,
}

// Define a type-safe key
const CONFIG: Key<AppConfig> = Key::new("app_config");

async fn example(client: &bitwarden_core::Client) -> Result<(), Box<dyn std::error::Error>> {
    // Get setting
    let config: Option<AppConfig> = client.settings().get(CONFIG).await?;

    // Set setting
    let new_config = AppConfig {
        theme: "dark".to_string(),
        auto_save: true,
    };
    client.settings().set(CONFIG, new_config).await?;

    // Remove setting
    client.settings().remove(CONFIG).await?;

    Ok(())
}
```

## Database Setup

Include the settings migration when initializing your database:

```rust
use bitwarden_settings::get_settings_migration_step;
use bitwarden_state::repository::RepositoryMigrations;

let migrations = RepositoryMigrations::new(vec![
    get_settings_migration_step(),
    // ... other migrations
]);
```

## Architecture

Settings are stored as JSON values in a SQLite database using the SDK's repository pattern. Each
setting is identified by a string key and serialized to JSON for storage. The `Key<T>` type provides
compile-time type safety while maintaining flexibility.

## Layer

This is a **Feature Implementation** layer crate that:

- Builds on **Core Infrastructure** (bitwarden-state)
- Provides reusable settings functionality
- Can be used by applications (bw CLI) or other feature crates
