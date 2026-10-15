# Bitwarden Managed Settings

Provides [`ManagedSettingsClient`], the SDK's read handle onto the settings an organization's IT
administrators enforce through the host operating system's Unified Endpoint Management (UEM)
channel.

The host application constructs a [`ManagedSettingsClient`] at startup with
[`ManagedSettingsClient::new`], acquires a [`ManagementProfile`] from the host platform, and pushes
it in with [`ManagedSettingsClient::update_profile`]. Passing `None` clears the profile. Clones of
the handle share one profile, so an update pushed through any clone is observed by all of them.

The same shared cell, obtained from [`ManagedSettingsClient::cell`], is handed to
[`bitwarden_core::ClientBuilder::with_managed_profile`], so SDK feature crates read the current
profile through [`ManagedSettingsClientExt::managed_settings`] on a [`bitwarden_core::Client`]. A
client built without a cell gets a fresh empty one and simply manages nothing.

Consumers read a value with [`ManagedSettingsClient::get`] for the raw JSON-encoded string, or
decode it into a concrete type with [`ManagementProfile::get_as`] on the profile returned by
[`ManagedSettingsClient::current_profile`]. Guard writes to the corresponding state with
[`ManagedSettingsClient::is_managed`], only writing when the key is not administrator-forced.

The first profile push is asynchronous on every platform, so a consumer may not observe a managed
setting immediately after startup.

Generally, a managed setting overrides user state, global state, and any defaults. When a policy and
a managed setting both affect a given setting, the consuming feature is responsible for resolving
the conflict.

## Consuming a setting

A feature crate reads through [`ManagedSettingsClientExt::managed_settings`]. Use the managed value
when present, fall back to the user's value otherwise, and refuse user writes to a managed key:

```rust
# use std::collections::HashMap;
# use bitwarden_core::ClientBuilder;
# use bitwarden_managed_settings::{ManagedSettingsClient, ManagementProfile};
use bitwarden_core::Client;
use bitwarden_managed_settings::ManagedSettingsClientExt;

const PASSWORD_LENGTH: &str = "generator.password.length";

fn password_length(client: &Client, user_value: u32) -> u32 {
    let Some(profile) = client.managed_settings().current_profile() else {
        return user_value;
    };
    match profile.get_as::<u32>(PASSWORD_LENGTH) {
        Ok(Some(length)) => length,
        Ok(None) => user_value,
        Err(error) => {
            tracing::warn!(%error, "Ignoring malformed managed setting");
            user_value
        }
    }
}

fn set_password_length(client: &Client, length: u32) -> Result<(), &'static str> {
    if client.managed_settings().is_managed(PASSWORD_LENGTH.to_string()) {
        return Err("Password length is set by your administrator");
    }
    // Persist `length` to user state.
    Ok(())
}
# let host = ManagedSettingsClient::new();
# let client = ClientBuilder::new().with_managed_profile(host.cell()).build();
# host.update_profile(Some(ManagementProfile {
#     version: 1,
#     updated_at: 0,
#     settings: HashMap::from([(PASSWORD_LENGTH.to_string(), "20".to_string())]),
# }));

assert_eq!(client.managed_settings().get(PASSWORD_LENGTH.to_string()).as_deref(), Some("20"));
assert_eq!(password_length(&client, 14), 20);
assert!(set_password_length(&client, 16).is_err());
```

[`ManagedSettingsClient::is_managed`] tests key presence only, so a key whose value fails to decode
still reports as managed. The SDK exposes no change notification, so read at the point of use rather
than caching a value.

## Adding a new setting key

The SDK has no key registry or key constants. A key is a string shared by the consuming feature and
the administrator's configuration, and the SDK accepts whatever keys the host pushes.

- **Naming**: the host flattens the administrator's nested configuration object into dotted keys, so
  `{"generator": {"password": {"length": 20}}}` arrives as `generator.password.length`. Follow the
  existing `environment.*` keys: lead with the feature area and use camelCase segments
  (`environment.webVault`). Never put a dot inside a segment; no escape syntax exists, so
  `{"a.b": 1}` and `{"a": {"b": 1}}` collide.
- **Value shape**: each value is the JSON encoding of one leaf, so `20` is stored as `"20"` and
  `"https://vault.example.com"` as `"\"https://vault.example.com\""`. Only objects are flattened, so
  a leaf is a JSON scalar or array.
- **Decoding**: read with [`ManagementProfile::get_as`] into the matching Rust type (`bool`, a
  number, `String`, or `Vec<_>`). A mismatched value returns
  [`ManagedSettingsError::Decode`](bitwarden_managed_settings_types::ManagedSettingsError::Decode).

To test, build a [`ManagementProfile`], push it through a host handle into a client, and assert on
the read:

```rust
use std::collections::HashMap;

use bitwarden_core::ClientBuilder;
use bitwarden_managed_settings::{
    ManagedSettingsClient, ManagedSettingsClientExt, ManagementProfile,
};

let host = ManagedSettingsClient::new();
let client = ClientBuilder::new().with_managed_profile(host.cell()).build();

host.update_profile(Some(ManagementProfile {
    version: 1,
    updated_at: 0,
    settings: HashMap::from([("generator.password.length".to_string(), "20".to_string())]),
}));

let profile = client.managed_settings().current_profile().expect("profile was pushed");
assert_eq!(profile.get_as::<u32>("generator.password.length").unwrap(), Some(20));
```

Also cover the unmanaged case and a malformed value.

## Host acquisition wiring

The host constructs one [`ManagedSettingsClient`] at startup and passes its
[`cell`](ManagedSettingsClient::cell) to [`bitwarden_core::ClientBuilder::with_managed_profile`]. It
then reads the profile from the platform, normalizes it into a [`ManagementProfile`], and pushes it
with [`ManagedSettingsClient::update_profile`], again whenever the platform reports a change:

```rust
use bitwarden_core::ClientBuilder;
use bitwarden_managed_settings::{ManagedSettingsClient, ManagementProfile};

# fn read_platform_profile() -> Option<ManagementProfile> { None }
let managed_settings = ManagedSettingsClient::new();
let client = ClientBuilder::new()
    .with_managed_profile(managed_settings.cell())
    .build();

managed_settings.update_profile(read_platform_profile());
```

`PasswordManagerClient::new_with_client_tokens` in `bitwarden-pm` performs the builder step, and
both binding surfaces wrap it:

- **WASM** (`bitwarden-wasm-internal`): [`ManagedSettingsClient`] is exported directly with `new`,
  `update_profile`, `is_managed`, and `get`. The host passes it to the `PasswordManagerClient`
  constructor, and `PasswordManagerClient::managed_settings` returns a handle onto the same profile.
- **UniFFI** (`bitwarden-uniffi`): `ManagedSettingsBindingClient` wraps [`ManagedSettingsClient`]
  with the same four methods and is a required argument to `Client::new`.

The UniFFI bindings exist, but no mobile client feeds them yet. iOS passes an inert
`ManagedSettingsBindingClient()` and reads MDM configuration through its own
`com.apple.configuration.managed` path
([bitwarden/ios#2989](https://github.com/bitwarden/ios/pull/2989)).

## Current limitations

- The first profile push is asynchronous, so reads made before it see no profile.
- Managed settings never apply transparently. Each feature opts in by reading its keys explicitly.
- Conflicts between a policy and a managed setting are resolved by the consuming feature.
- Only the browser extension (Chrome and Firefox, in `bitwarden/clients`) acquires a profile.
- Desktop acquisition is proposed, not shipped
  ([PM-43024](https://bitwarden.atlassian.net/browse/PM-43024), blocked on
  [PM-44588](https://bitwarden.atlassian.net/browse/PM-44588)).
- The web vault, CLI, and Safari extension have no acquisition path.
- Mobile clients need client-side acquisition before they can feed the UniFFI bindings.
