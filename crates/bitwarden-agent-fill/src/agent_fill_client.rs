use bitwarden_core::{Client, FromClient};

use crate::AgentFillApprovalClient;

/// Client for agent fill operations.
#[derive(Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
#[bitwarden_ffi::wasm_object]
pub struct AgentFillClient {
    client: Client,
}

impl AgentFillClient {
    fn new(client: Client) -> Self {
        Self { client }
    }
}

#[bitwarden_ffi::wasm_export]
#[cfg_attr(feature = "uniffi", uniffi::export)]
impl AgentFillClient {
    /// Approval request and response operations.
    pub fn approvals(&self) -> AgentFillApprovalClient {
        AgentFillApprovalClient::from_client(&self.client)
    }
}

/// Extension trait to add the agent fill client to the main Bitwarden SDK client.
pub trait AgentFillClientExt {
    /// Get the agent fill client.
    fn agent_fill(&self) -> AgentFillClient;
}

impl AgentFillClientExt for Client {
    fn agent_fill(&self) -> AgentFillClient {
        AgentFillClient::new(self.clone())
    }
}
