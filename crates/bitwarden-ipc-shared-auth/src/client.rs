use std::sync::Arc;

pub struct SharedAuthClient {
    inner: Arc<InnerSharedAuthClient>,
}

struct InnerSharedAuthClient {
    client_manager: bitwarden_client_manager::ClientManager,
    ipc_client: bitwarden_ipc::IpcClient<>,
}
