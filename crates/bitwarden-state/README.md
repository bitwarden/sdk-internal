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

#### How to use it on web clients

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

#### How to use it on iOS

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

### How to use it on Android

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
