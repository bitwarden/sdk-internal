use crate::ipc_client;

// WASM-compatible configuration of the IPC client.
#[cfg(feature = "wasm")]
#[allow(missing_docs)]
pub type DefaultIpcClient = ipc_client::IpcClientImpl<
    crate::traits::NoEncryptionCryptoProvider,
    crate::wasm::JsCommunicationBackend,
    crate::wasm::GenericSessionRepository,
>;

// Test configuration of the IPC client backed by a test communication backend and in-memory
// session storage.
#[cfg(all(not(feature = "wasm"), feature = "test-support"))]
#[allow(missing_docs)]
pub type DefaultIpcClient = ipc_client::IpcClientImpl<
    crate::traits::NoEncryptionCryptoProvider,
    crate::traits::TestCommunicationBackend,
    crate::traits::InMemorySessionRepository<()>,
>;

// No-op configuration of the IPC client.
#[cfg(not(any(feature = "wasm", feature = "test-support")))]
#[allow(missing_docs)]
pub type DefaultIpcClient = ipc_client::IpcClientImpl<
    crate::traits::NoEncryptionCryptoProvider,
    crate::traits::NoopCommunicationBackend,
    crate::traits::InMemorySessionRepository<()>,
>;
