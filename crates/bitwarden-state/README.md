# bitwarden-state

This crate contains the core state handling code of the Bitwarden SDK. Its primary feature is a
namespaced key-value store, accessible via the typed [Repository](crate::repository::Repository)
trait.

To make use of the `Repository` trait, the first thing to do is to ensure the data to be used with
it is registered to do so:

```rust
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct Cipher {
    // Cipher fields
}

// Register `Cipher` for use with a `Repository`.
// This should be done in the crate where `Cipher` is defined.
bitwarden_state::register_repository_item!(String => Cipher, "Cipher");
```

With the registration complete, the next important decision is to select where will the data be
stored:

- If the application using the SDK is responsible for storing the data, it must provide its own
  implementation of the `Repository` trait. We call this approach `Client-Managed State` or
  `Application-Managed State`. See the next section for details on how to implement this.

- If the SDK itself will handle data storage, we call that approach `SDK-Managed State`. The
  implementation of this is will a work in progress.

Note that these approaches aren't mutually exclusive: a repository item can use both client and SDK
managed state at the same time. However, this mixed approach is only recommended during migration
scenarios to avoid potential confusion.

## Client-Managed State

With `Client-Managed State` the application and SDK will both access the same data pool, which
simplifies the initial migration and development. Using this approach requires manual setup, as we
need to define some functions in `bitwarden-wasm-internal` and `bitwarden-uniffi` to allow the
applications to provide their `Repository` implementations. The implementations themselves will be
very simple as we provide macros that take care of the brunt of the work.

To add support for a new `Repository`, add it to the list defined at the end of
`crates/bitwarden-pm/src/migrations.rs`.

```rust
macro_rules! create_client_managed_repositories {
    ($container_name:ident, $macro:ident) => {
        $macro! {
            $container_name;
            // List any SDK-managed repositories here. The format is:
            // <fully qualified path to the item>, <item type idenfier>, <field name>, <name of the repository implementation>
            ::bitwarden_vault::Cipher, Cipher, cipher, CipherRepository;
            ::bitwarden_vault::Folder, Folder, folder, FolderRepository;
        }
    };
}
```

#### How to initialize Client-Managed State on the web clients

Once we have the function defined in `bitwarden-wasm-internal`, we can use it from the web clients.
For that, the first thing we need to do is create a mapper between the client and SDK types. This
mapper will also contain the `UserKeyDefinition` for the `StateProvider` API and should be created
in the folder of the team that owns the model:

```typescript
export class CipherRecordMapper implements SdkRecordMapper<CipherData, SdkCipher> {
  userKeyDefinition(): UserKeyDefinition<Record<string, CipherData>> {
    return ENCRYPTED_CIPHERS;
  }

  toSdk(value: CipherData): SdkCipher {
    return new Cipher(value).toSdkCipher();
  }

  fromSdk(value: SdkCipher): CipherData {
    throw new Error("Cipher.fromSdk is not implemented yet");
  }
}
```

Once that is done, we should be able to register the mapper in the
`libs/common/src/platform/services/sdk/client-managed-state.ts` file, inside the `initializeState`
function:

```typescript
export async function initializeState(
  userId: UserId,
  stateClient: StateClient,
  stateProvider: StateProvider,
): Promise<void> {
  stateClient.register_client_managed_repositories({
    cipher: new RepositoryRecord(userId, stateProvider, new CipherRecordMapper()),
  });
}
```

#### How to initialize Client-Managed State on iOS

Once we have the function defined in `bitwarden-uniffi`, we can use it from the iOS application:

```swift
class CipherStoreImpl: CipherStore {
    private var cipherDataStore: CipherDataStore
    private var userId: String

    init(cipherDataStore: CipherDataStore, userId: String) {
        self.cipherDataStore = cipherDataStore
        self.userId = userId
    }

    func get(id: String) async -> Cipher? {
        return try await cipherDataStore.fetchCipher(withId: id, userId: userId)
    }

    func list() async  -> [Cipher] {
        return try await cipherDataStore.fetchAllCiphers(userId: userId)
    }

    func set(id: String, value: Cipher) async { }

    func remove(id: String) async { }
}

let store = CipherStoreImpl(cipherDataStore: self.cipherDataStore, userId: userId);
try await self.clientService.platform().store().registerCipherStore(store: store);
```

### How to initialize Client-Managed State on Android

Once we have the function defined in `bitwarden-uniffi`, we can use it from the Android application:

```kotlin
val vaultDiskSource: VaultDiskSource ;

class CipherStoreImpl: CipherStore {
    override suspend fun get(id: String): Cipher? {
        return vaultDiskSource.getCiphers(userId).firstOrNull()
            .orEmpty().firstOrNull { it.id == id }?.toEncryptedSdkCipher()
    }

    override suspend fun list(): List<Cipher> {
        return vaultDiskSource.getCiphers(userId).firstOrNull()
            .orEmpty().map { it.toEncryptedSdkCipher() }
    }

    override suspend fun set(id: String, value: Cipher) {
        TODO("Not yet implemented")
    }

    override suspend fun remove(id: String) {
        TODO("Not yet implemented")
    }
}

getClient(userId = userId).platform().store().registerCipherStore(CipherStoreImpl());
```

## SDK-Managed State

<div class="warning">

SDK-Managed State is currently **not supported for WASM or UniFFI clients** due to the following
limitations:

- Migrations between versions of state are not supported
- Secure storage is not supported as a state storage mechanism
- Reactivity is not supported
- Browser extension-specific state synchronization mechanisms are not present

For these SDK clients, we recommend that they use client-managed state.

</div>

With `SDK-Managed State`, the SDK will be exclusively responsible for the data storage. This means
that the clients don't need to make any changes themselves, as the implementation is internal to the
SDK. To add support for an SDK managed `Repository`, a new migration step needs to be added to the
`bitwarden-state-migrations` crate.

### How to initialize SDK-Managed State

Go to `crates/bitwarden-pm/src/migrations.rs` and add a line with your type, as shown below. In this
example we're registering `Cipher` and `Folder` as SDK managed.

```rust,ignore
/// Returns a list of all SDK-managed repository migrations.
pub fn get_sdk_managed_migrations() -> RepositoryMigrations {
    use RepositoryMigrationStep::*;
    RepositoryMigrations::new(vec![
        // Add any new migrations here. Note that order matters, and that removing a repository
        // requires a separate migration step using `Remove(...)`.
        Add(Cipher::data()),
        Add(Folder::data()),
    ])
}
```

## Values

This crate also provides a type-safe API for individual named values, such as the active user or the
last sync time. Where a repository holds a collection keyed by id, a value is a singleton the SDK
reads and writes by itself.

### Usage

```rust
use bitwarden_state::{register_value_key, Value};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct AppConfig {
    theme: String,
    auto_save: bool,
}

register_value_key!(pub CONFIG: AppConfig = "app_config");

struct TestClient {
    // Obtained from bitwarden_core::Client.platform().state().value::<CONFIG>(),
    // or injected with #[derive(FromClient)]
    app_config: Value<CONFIG>,
}

async fn example(client: &TestClient) -> Result<(), Box<dyn std::error::Error>> {
    // Read, erroring if the value has never been written
    let config: AppConfig = client.app_config.get().await?;

    // Read, treating absence as an expected outcome
    let config: Option<AppConfig> = client.app_config.get_opt().await?;

    client
        .app_config
        .set(AppConfig {
            theme: "dark".to_string(),
            auto_save: true,
        })
        .await?;

    client.app_config.remove().await?;

    Ok(())
}
```

`register_value_key!` emits a marker type carrying the storage name and the value type, so
`Value<CONFIG>` identifies exactly one value and injection with `#[derive(FromClient)]` falls out for
free.

The older `Setting<T>` handle, addressed by a `Key<T>` passed at runtime, still works and reads the
same storage. Both spellings come from one declaration, so call sites migrate independently.

## Testing

Most tests run as standard `cargo test` against the native target — the SQLite backend uses
in-memory connections and the in-memory backend needs no special setup.

```bash
cargo test -p bitwarden-state --all-features
```

### IndexedDB browser tests

The IndexedDB backend is only reachable on `wasm32-unknown-unknown` and requires a real browser
because IndexedDB is a browser API. These tests live under
[tests/indexed_db.rs](./tests/indexed_db.rs) and are gated behind the `browser-tests` feature so
they don't break the default WASM build for contributors without a webdriver installed.

To run them locally:

```bash
cargo test --target wasm32-unknown-unknown -p bitwarden-state --features wasm,browser-tests
```

The `wasm-bindgen-test-runner` will pick the first webdriver it finds on `PATH`. On macOS the
easiest option is geckodriver:

```bash
brew install geckodriver
brew install --cask firefox   # if not already installed
```

Alternatives:

- **Chrome**: `brew install --cask chromedriver` (and `google-chrome`). Chromedriver and Chrome
  versions must match.
- **Safari**: ships with macOS. Enable with `sudo safaridriver --enable` and then in Safari: Develop
  → Allow Remote Automation.

To force a specific driver regardless of what else is on `PATH`:

```bash
GECKODRIVER=$(which geckodriver) cargo test --target wasm32-unknown-unknown \
    -p bitwarden-state --features wasm,browser-tests
```
