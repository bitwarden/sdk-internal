use bitwarden_core::Client;

use crate::access_policies::{
    AccessPoliciesResponse, GetGrantedPoliciesError, GetGrantedPoliciesRequest,
    GetPotentialGranteesError, GetPotentialGranteesRequest, GetProjectAccessPoliciesError,
    GetProjectAccessPoliciesRequest, GetSecretAccessPoliciesError, GetSecretAccessPoliciesRequest,
    GrantedPoliciesResponse, PotentialGranteesResponse, PutGrantedPoliciesError,
    PutGrantedPoliciesRequest, PutProjectAccessPoliciesError, PutProjectAccessPoliciesRequest,
    get_granted_policies, get_potential_grantees, get_project_access_policies,
    get_secret_access_policies, put_granted_policies, put_project_access_policies,
};

#[allow(missing_docs)]
pub struct AccessPoliciesClient {
    pub(crate) client: Client,
}

impl AccessPoliciesClient {
    #[allow(missing_docs)]
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    #[allow(missing_docs)]
    pub async fn get_project_policies(
        &self,
        input: &GetProjectAccessPoliciesRequest,
    ) -> Result<AccessPoliciesResponse, GetProjectAccessPoliciesError> {
        get_project_access_policies(&self.client, input).await
    }

    #[allow(missing_docs)]
    pub async fn put_project_policies(
        &self,
        input: &PutProjectAccessPoliciesRequest,
    ) -> Result<AccessPoliciesResponse, PutProjectAccessPoliciesError> {
        put_project_access_policies(&self.client, input).await
    }

    #[allow(missing_docs)]
    pub async fn get_secret_policies(
        &self,
        input: &GetSecretAccessPoliciesRequest,
    ) -> Result<AccessPoliciesResponse, GetSecretAccessPoliciesError> {
        get_secret_access_policies(&self.client, input).await
    }

    #[allow(missing_docs)]
    pub async fn get_granted_policies(
        &self,
        input: &GetGrantedPoliciesRequest,
    ) -> Result<GrantedPoliciesResponse, GetGrantedPoliciesError> {
        get_granted_policies(&self.client, input).await
    }

    #[allow(missing_docs)]
    pub async fn put_granted_policies(
        &self,
        input: &PutGrantedPoliciesRequest,
    ) -> Result<GrantedPoliciesResponse, PutGrantedPoliciesError> {
        put_granted_policies(&self.client, input).await
    }

    #[allow(missing_docs)]
    pub async fn get_potential_grantees(
        &self,
        input: &GetPotentialGranteesRequest,
    ) -> Result<PotentialGranteesResponse, GetPotentialGranteesError> {
        get_potential_grantees(&self.client, input).await
    }
}

#[allow(missing_docs)]
pub trait AccessPoliciesClientExt {
    #[allow(missing_docs)]
    fn access_policies(&self) -> AccessPoliciesClient;
}

impl AccessPoliciesClientExt for Client {
    fn access_policies(&self) -> AccessPoliciesClient {
        AccessPoliciesClient::new(self.clone())
    }
}
