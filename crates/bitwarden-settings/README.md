# bitwarden-settings

Type-safe settings repository for storing application configuration and state using type-safe keys.
Backed by the SDK's repository pattern.

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
