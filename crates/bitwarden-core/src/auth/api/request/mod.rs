#[cfg(feature = "secrets")]
mod access_token_request;
#[cfg(feature = "secrets")]
pub(crate) use access_token_request::*;

mod api_token_request;
pub(crate) use api_token_request::*;

#[cfg(feature = "internal")]
mod password_token_request;
use bitwarden_api_api::Configuration;
#[cfg(feature = "internal")]
pub(crate) use password_token_request::*;

mod renew_token_request;
pub(crate) use renew_token_request::*;

mod auth_request_token_request;
#[cfg(feature = "internal")]
pub(crate) use auth_request_token_request::*;

use crate::{
    ApiError,
    auth::{
        api::response::{IdentityTokenResponse, parse_identity_response},
        login::LoginError,
    },
};

pub(crate) async fn send_identity_connect_request(
    identity_config: &Configuration,
    body: impl serde::Serialize,
) -> Result<IdentityTokenResponse, LoginError> {
    let response = identity_config
        .client
        .post(format!("{}/connect/token", identity_config.base_path))
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded; charset=utf-8",
        )
        .header(reqwest::header::ACCEPT, "application/json")
        .body(serde_qs::to_string(&body).expect("Serialize should be infallible"))
        .send()
        .await
        .map_err(ApiError::from)?;

    let status = response.status();
    let text = response.text().await.map_err(ApiError::from)?;

    parse_identity_response(status, text)
}

#[cfg(test)]
mod tests {
    use serde::Serialize;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers};

    use super::*;

    #[derive(Serialize)]
    struct Body {
        password: String,
        client_secret: String,
        scope: String,
    }

    /// Identity decodes the body as `application/x-www-form-urlencoded`, so every value must
    /// survive that decoding unchanged, including characters with special meaning in the format.
    #[tokio::test]
    async fn identity_request_body_roundtrips_form_special_characters() {
        let server = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/connect/token"))
            .respond_with(ResponseTemplate::new(400).set_body_string("{}"))
            .mount(&server)
            .await;

        let config = Configuration {
            base_path: server.uri(),
            client: reqwest_middleware::ClientBuilder::new(bitwarden_api_base::new_http_client())
                .build(),
        };
        let body = Body {
            password: "a+b/c==%41&x=y #é".to_string(),
            client_secret: "100%".to_string(),
            scope: "api offline_access".to_string(),
        };

        let _ = send_identity_connect_request(&config, &body).await;

        let requests = server
            .received_requests()
            .await
            .expect("requests are recorded");
        assert_eq!(requests.len(), 1);
        let decoded: Vec<(String, String)> = url::form_urlencoded::parse(&requests[0].body)
            .into_owned()
            .collect();
        assert_eq!(
            decoded,
            vec![
                ("password".to_string(), body.password),
                ("client_secret".to_string(), body.client_secret),
                ("scope".to_string(), body.scope),
            ]
        );
    }
}
