use bitwarden_api_base::AuthRequired;

/// One-shot middleware that attaches a specific send access token to outgoing
/// requests opting into bearer auth via [`AuthRequired::Bearer`].
///
/// Constructed fresh per send-access call by [`SendClient::access_send`](crate::SendClient)
/// and [`SendClient::get_file_download_data`](crate::SendClient). Because the token lives
/// on this instance (not in shared state), concurrent send-access calls cannot observe
/// each other's tokens — eliminating the race where two callers' bearer tokens could be
/// swapped mid-flight.
#[derive(Clone)]
pub(crate) struct SendAccessTokenHandler {
    token: String,
}

impl SendAccessTokenHandler {
    pub(crate) fn new(token: String) -> Self {
        Self { token }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl reqwest_middleware::Middleware for SendAccessTokenHandler {
    async fn handle(
        &self,
        mut req: reqwest::Request,
        ext: &mut http::Extensions,
        next: reqwest_middleware::Next<'_>,
    ) -> Result<reqwest::Response, reqwest_middleware::Error> {
        if ext.get::<AuthRequired>().is_some() {
            match format!("Bearer {}", self.token).parse() {
                Ok(header_value) => {
                    req.headers_mut()
                        .insert(http::header::AUTHORIZATION, header_value);
                }
                Err(e) => {
                    tracing::warn!("Failed to parse send access token for header: {e}");
                }
            }
        }
        next.run(req, ext).await
    }
}

#[cfg(test)]
mod tests {
    use wiremock::MockServer;

    use super::*;

    async fn test_setup(token: &str) -> (reqwest_middleware::ClientWithMiddleware, MockServer) {
        let client = reqwest_middleware::ClientBuilder::new(reqwest::Client::new())
            .with(SendAccessTokenHandler::new(token.to_string()))
            .build();

        let server = MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&server)
            .await;

        (client, server)
    }

    #[tokio::test]
    async fn attaches_bearer_token_when_auth_required() {
        let (client, server) = test_setup("send-access-token").await;

        client
            .get(format!("{}/sends/access", server.uri()))
            .with_extension(AuthRequired::Bearer)
            .send()
            .await
            .unwrap();

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0]
                .headers
                .get("Authorization")
                .map(|v| v.to_str().unwrap()),
            Some("Bearer send-access-token")
        );
    }

    #[tokio::test]
    async fn does_not_attach_token_without_auth_required() {
        let (client, server) = test_setup("send-access-token").await;

        client
            .get(format!("{}/test", server.uri()))
            .send()
            .await
            .unwrap();

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].headers.get("Authorization"), None);
    }
}
