use bitwarden_core::Client;

use crate::{
    error::SecretsManagerError,
    secrets::{
        SecretCreateRequest, SecretGetRequest, SecretIdentifiersByProjectRequest,
        SecretIdentifiersRequest, SecretIdentifiersResponse, SecretPutRequest, SecretResponse,
        SecretsDeleteRequest, SecretsDeleteResponse, SecretsGetRequest, SecretsResponse,
        SecretsSyncRequest, SecretsSyncResponse, create_secret, delete_secrets, get_secret,
        get_secrets_by_ids, list_secrets, list_secrets_by_project, sync_secrets, update_secret,
    },
};

/// Aliases to maintain backward compatibility
pub type ClientSecrets = SecretsClient;

#[allow(missing_docs)]
pub struct SecretsClient {
    client: Client,
}

impl SecretsClient {
    #[allow(missing_docs)]
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    #[allow(missing_docs)]
    pub async fn get(
        &self,
        input: &SecretGetRequest,
    ) -> Result<SecretResponse, SecretsManagerError> {
        get_secret(&self.client, input).await
    }

    #[allow(missing_docs)]
    pub async fn get_by_ids(
        &self,
        input: SecretsGetRequest,
    ) -> Result<SecretsResponse, SecretsManagerError> {
        get_secrets_by_ids(&self.client, input).await
    }

    #[allow(missing_docs)]
    pub async fn create(
        &self,
        input: &SecretCreateRequest,
    ) -> Result<SecretResponse, SecretsManagerError> {
        create_secret(&self.client, input).await
    }

    #[allow(missing_docs)]
    pub async fn list(
        &self,
        input: &SecretIdentifiersRequest,
    ) -> Result<SecretIdentifiersResponse, SecretsManagerError> {
        list_secrets(&self.client, input).await
    }

    #[allow(missing_docs)]
    pub async fn list_by_project(
        &self,
        input: &SecretIdentifiersByProjectRequest,
    ) -> Result<SecretIdentifiersResponse, SecretsManagerError> {
        list_secrets_by_project(&self.client, input).await
    }

    #[allow(missing_docs)]
    pub async fn update(
        &self,
        input: &SecretPutRequest,
    ) -> Result<SecretResponse, SecretsManagerError> {
        update_secret(&self.client, input).await
    }

    #[allow(missing_docs)]
    pub async fn delete(
        &self,
        input: SecretsDeleteRequest,
    ) -> Result<SecretsDeleteResponse, SecretsManagerError> {
        delete_secrets(&self.client, input).await
    }

    #[allow(missing_docs)]
    pub async fn sync(
        &self,
        input: &SecretsSyncRequest,
    ) -> Result<SecretsSyncResponse, SecretsManagerError> {
        sync_secrets(&self.client, input).await
    }
}

/// This trait is for backward compatibility
pub trait ClientSecretsExt {
    #[allow(missing_docs)]
    fn secrets(&self) -> ClientSecrets;
}

impl ClientSecretsExt for Client {
    fn secrets(&self) -> ClientSecrets {
        SecretsClient::new(self.clone())
    }
}

#[allow(missing_docs)]
pub trait SecretsClientExt {
    #[allow(missing_docs)]
    fn secrets(&self) -> SecretsClient;
}

impl SecretsClientExt for Client {
    fn secrets(&self) -> SecretsClient {
        SecretsClient::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::{
        Client, ClientSettings, DeviceType, auth::login::AccessTokenLoginRequest,
    };

    use crate::{
        ClientSecretsExt,
        secrets::{SecretGetRequest, SecretIdentifiersRequest},
    };

    async fn start_mock(mocks: Vec<wiremock::Mock>) -> (wiremock::MockServer, Client) {
        let server = wiremock::MockServer::start().await;

        for mock in mocks {
            server.register(mock).await;
        }

        let settings = ClientSettings {
            identity_url: format!("http://{}/identity", server.address()),
            api_url: format!("http://{}/api", server.address()),
            user_agent: "Bitwarden Rust-SDK [TEST]".into(),
            device_type: DeviceType::SDK,
        };

        (server, Client::new(Some(settings)))
    }

    #[tokio::test]
    async fn test_access_token_login() {
        use wiremock::{Mock, ResponseTemplate, matchers};

        // Create the mock server with the necessary routes for this test
        let (_server, client) = start_mock(vec![
            Mock::given(matchers::path("/identity/connect/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({
                    "access_token":"eyJhbGciOiJSUzI1NiIsImtpZCI6IjMwMURENkE1MEU4NEUxRDA5MUM4MUQzQjAwQkY5MDEwQzg1REJEOUFSUzI1NiIsInR5cCI6\
                    ImF0K2p3dCIsIng1dCI6Ik1CM1dwUTZFNGRDUnlCMDdBTC1RRU1oZHZabyJ9.eyJuYmYiOjE2NzUxMDM3ODEsImV4cCI6MTY3NTEwNzM4MSwiaXNzIjo\
                    iaHR0cDovL2xvY2FsaG9zdCIsImNsaWVudF9pZCI6ImVjMmMxZDQ2LTZhNGItNDc1MS1hMzEwLWFmOTYwMTMxN2YyZCIsInN1YiI6ImQzNDgwNGNhLTR\
                    mNmMtNDM5Mi04NmI3LWFmOTYwMTMxNzVkMCIsIm9yZ2FuaXphdGlvbiI6ImY0ZTQ0YTdmLTExOTAtNDMyYS05ZDRhLWFmOTYwMTMxMjdjYiIsImp0aSI\
                    6IjU3QUU0NzQ0MzIwNzk1RThGQkQ4MUIxNDA2RDQyNTQyIiwiaWF0IjoxNjc1MTAzNzgxLCJzY29wZSI6WyJhcGkuc2VjcmV0cyJdfQ.GRKYzqgJZHEE\
                    ZHsJkhVZH8zjYhY3hUvM4rhdV3FU10WlCteZdKHrPIadCUh-Oz9DxIAA2HfALLhj1chL4JgwPmZgPcVS2G8gk8XeBmZXowpVWJ11TXS1gYrM9syXbv9j\
                    0JUCdpeshH7e56WnlpVynyUwIum9hmYGZ_XJUfmGtlKLuNjYnawTwLEeR005uEjxq3qI1kti-WFnw8ciL4a6HLNulgiFw1dAvs4c7J0souShMfrnFO3g\
                    SOHff5kKD3hBB9ynDBnJQSFYJ7dFWHIjhqs0Vj-9h0yXXCcHvu7dVGpaiNjNPxbh6YeXnY6UWcmHLDtFYsG2BWcNvVD4-VgGxXt3cMhrn7l3fSYuo32Z\
                    Yk4Wop73XuxqF2fmfmBdZqGI1BafhENCcZw_bpPSfK2uHipfztrgYnrzwvzedz0rjFKbhDyrjzuRauX5dqVJ4ntPeT9g_I5n71gLxiP7eClyAx5RxdF6\
                    He87NwC8i-hLBhugIvLTiDj-Sk9HvMth6zaD0ebxd56wDjq8-CMG_WcgusDqNzKFHqWNDHBXt8MLeTgZAR2rQMIMFZqFgsJlRflbig8YewmNUA9wAU74\
                    TfxLY1foO7Xpg49vceB7C-PlvGi1VtX6F2i0tc_67lA5kWXnnKBPBUyspoIrmAUCwfms5nTTqA9xXAojMhRHAos_OdM",
                    "expires_in":3600,
                    "token_type":"Bearer",
                    "scope":"api.secrets",
                    "encrypted_payload":"2.E9fE8+M/VWMfhhim1KlCbQ==|eLsHR484S/tJbIkM6spnG/HP65tj9A6Tba7kAAvUp+rYuQmGLixiOCfMsqt5OvBctDfvvr/Aes\
                    Bu7cZimPLyOEhqEAjn52jF0eaI38XZfeOG2VJl0LOf60Wkfh3ryAMvfvLj3G4ZCNYU8sNgoC2+IQ==|lNApuCQ4Pyakfo/wwuuajWNaEX/2MW8/3rjXB/V7n+k="})
            )),
            Mock::given(matchers::path("/api/organizations/f4e44a7f-1190-432a-9d4a-af96013127cb/secrets"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({
                    "secrets":[{
                            "id":"15744a66-341a-4c62-af50-af960166b6bc",
                            "organizationId":"f4e44a7f-1190-432a-9d4a-af96013127cb",
                            "key":"2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8=",
                            "creationDate":"2023-01-26T21:46:02.2182556Z",
                            "revisionDate":"2023-01-26T21:46:02.2182557Z"
                    }],
                    "projects":[],
                    "object":"SecretsWithProjectsList"
                })
            )),
            Mock::given(matchers::path("/api/secrets/15744a66-341a-4c62-af50-af960166b6bc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({
                    "id":"15744a66-341a-4c62-af50-af960166b6bc",
                    "organizationId":"f4e44a7f-1190-432a-9d4a-af96013127cb",
                    "key":"2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8=",
                    "value":"2.Gl34n9JYABC7V21qHcBzHg==|c1Ds244pob7i+8+MXe4++w==|Shimz/qKMYZmzSFWdeBzFb9dFz7oF6Uv9oqkws7rEe0=",
                    "note":"2.Cn9ABJy7+WfR4uUHwdYepg==|+nbJyU/6hSknoa5dcEJEUg==|1DTp/ZbwGO3L3RN+VMsCHz8XDr8egn/M5iSitGGysPA=",
                    "creationDate":"2023-01-26T21:46:02.2182556Z",
                    "revisionDate":"2023-01-26T21:46:02.2182557Z",
                    "object":"secret"
                })
            ))
        ]).await;

        // Test the login is correct and we store the returned organization ID correctly
        let res = client
            .auth()
            .login_access_token(&AccessTokenLoginRequest {
                access_token: "0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==".into(),
                state_file: None,
            })
            .await
            .unwrap();
        assert!(res.authenticated);

        let organization_id = "f4e44a7f-1190-432a-9d4a-af96013127cb".try_into().unwrap();

        // Test that we can retrieve the list of secrets correctly
        let mut res = client
            .secrets()
            .list(&SecretIdentifiersRequest { organization_id })
            .await
            .unwrap();
        assert_eq!(res.data.len(), 1);

        // Test that given a secret ID we can get it's data
        let res = client
            .secrets()
            .get(&SecretGetRequest {
                id: res.data.remove(0).id,
            })
            .await
            .unwrap();
        assert_eq!(res.key, "TEST");
        assert_eq!(res.note, "TEST");
        assert_eq!(res.value, "TEST");
    }
}
