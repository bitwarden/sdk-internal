use crate::ipc_client;

#[cfg(feature = "wasm")]
#[allow(missing_docs)]
pub type IpcClient = ipc_client::IpcClient<
    crate::traits::NoEncryptionCryptoProvider,
    crate::wasm::JsCommunicationBackend,
    crate::wasm::GenericSessionRepository,
>;

#[cfg(not(feature = "wasm"))]
#[allow(missing_docs)]
pub type IpcClient = ipc_client::IpcClient<
    crate::traits::NoEncryptionCryptoProvider,
    crate::traits::InMemoryCommunicationProvider,
    crate::traits::InMemorySessionRepository<()>,
>;
