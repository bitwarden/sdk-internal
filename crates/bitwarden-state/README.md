# bitwarden-state

This crate contains the core state handling code of the Bitwarden SDK. Its primary feature is a
namespaced key-value store, accessible via the typed [Repository](crate::repository::Repository)
trait.

To make use of the `Repository` trait, the first thing to do is to ensure the data to be used with
it is registered to do so:

```rust
struct Cipher {
    // Cipher fields
};

// Register `Cipher` for use with a `Repository`.
// This should be done in the crate where `Cipher` is defined.
bitwarden_state::register_repository_item!(Cipher, "Cipher");
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

### Client-Managed State in WASM

For WASM, we need to define a new `Repository` for our type and provide a function that will accept
it. This is done in the file `crates/bitwarden-wasm-internal/src/platform/mod.rs`, you can check the
provided example:

```rust,ignore
repository::create_wasm_repository!(CipherRepository, Cipher, "Repository<Cipher>");

#[wasm_bindgen]
impl StateClient {
    pub fn register_cipher_repository(&self, store: CipherRepository) {
        let store = store.into_channel_impl();
        self.0.platform().state().register_client_managed(store)
    }
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
  await stateClient.register_cipher_repository(
    new RepositoryRecord(userId, stateProvider, new CipherRecordMapper()),
  );
}
```

### Client-Managed State in UniFFI

For UniFFI, we need to define a new `Repository` for our type and provide a function that will
accept it. This is done in the file `crates/bitwarden-uniffi/src/platform/mod.rs`, you can check the
provided example:

```rust,ignore
repository::create_uniffi_repository!(CipherRepository, Cipher);

#[uniffi::export]
impl StateClient {
    pub fn register_cipher_repository(&self, store: Arc<dyn CipherRepository>) {
        let store_internal = UniffiRepositoryBridge::new(store);
        self.0
            .platform()
            .state()
            .register_client_managed(store_internal)
    }
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

With `SDK-Managed State`, the SDK will be exclusively responsible for the data storage. This means
that the clients don't need to make any changes themselves, as the implementation is internal to the
SDK. To add support for an SDK managed `Repository`, it needs to be added to the initialization code
for WASM and UniFFI. This example shows how to add support for `Cipher`s.

### How to initialize SDK-Managed State on WASM

Go to `crates/bitwarden-wasm-internal/src/platform/mod.rs` and add a line with your type, as shown
below. In this example we're registering `Cipher` as both client and SDK managed to show how both
are done, but you can also just do one or the other.

```rust,ignore
    pub async fn initialize_state(
        &self,
        cipher_repository: CipherRepository,
    ) -> Result<(), bitwarden_state::registry::StateRegistryError> {
        let cipher = cipher_repository.into_channel_impl();
        // Register the provided repository as client managed state
        self.0.platform().state().register_client_managed(cipher);

        let sdk_managed_repositories = vec![
            // This should list all the SDK-managed repositories
            <Cipher as RepositoryItem>::data(),
            // Add your type here
        ];

        self.0
            .platform()
            .state()
            .initialize_database(sdk_managed_repositories)
            .await
    }
```

### How to initialize SDK-Managed State on UniFFI

Go to `crates/bitwarden-uniffi/src/platform/mod.rs` and add a line with your type, as shown below.
In this example we're registering `Cipher` as both client and SDK managed to show how both are done,
but you can also just do one or the other.

```rust,ignore
    pub async fn initialize_state(
        &self,
        cipher_repository: Arc<dyn CipherRepository>,
    ) -> Result<()> {
        let cipher = UniffiRepositoryBridge::new(cipher_repository);
        // Register the provided repository as client managed state
        self.0.platform().state().register_client_managed(cipher);

        let sdk_managed_repositories = vec![
            // This should list all the SDK-managed repositories
            <Cipher as RepositoryItem>::data(),
            // Add your type here
        ];

        self.0
            .platform()
            .state()
            .initialize_database(sdk_managed_repositories)
            .await
            .map_err(Error::StateRegistry)?;
        Ok(())
    }
```
