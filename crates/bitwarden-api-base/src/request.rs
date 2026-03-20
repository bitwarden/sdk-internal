use http::header::CONTENT_TYPE;
use serde::de::{DeserializeOwned, Error as _};

use crate::{ContentType, Error, ResponseContent};

fn content_type(response: &reqwest::Response) -> ContentType {
    response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .into()
}

/// [process_with_json_response] is generic, which means it gets monomorphized for every type it's
/// used with. This function contains the non-generic logic for processing the response so that it
/// doesn't get duplicated.
#[inline(never)]
async fn process_with_json_response_internal<E>(
    request: reqwest_middleware::RequestBuilder,
) -> Result<String, crate::Error<E>> {
    let response = request.send().await?;
    let status = response.status();
    let content_type = content_type(&response);
    let content = response.text().await?;

    if !status.is_client_error() && !status.is_server_error() {
        match content_type {
            ContentType::Json => Ok(content),
            ct => Err(Error::from(serde_json::Error::custom(format!(
                "Received `{ct:?}` content type response when JSON was expected"
            )))),
        }
    } else {
        Err(Error::ResponseError(ResponseContent {
            status,
            content,
            entity: None,
        }))
    }
}

/// Sends and processes a request expecting a JSON response, deserializing it into the expected type
/// `T``.
pub async fn process_with_json_response<T: DeserializeOwned, E>(
    request: reqwest_middleware::RequestBuilder,
) -> Result<T, crate::Error<E>> {
    process_with_json_response_internal(request)
        .await
        .and_then(|content| serde_json::from_str(&content).map_err(Into::into))
}

/// Sends and processes a request expecting an empty response, returning `Ok(())` if the status code
/// indicates success.
#[inline(never)]
pub async fn process_with_empty_response<E>(
    request: reqwest_middleware::RequestBuilder,
) -> Result<(), crate::Error<E>> {
    let response = request.send().await?;
    let status = response.status();

    if !status.is_client_error() && !status.is_server_error() {
        Ok(())
    } else {
        let content = response.text().await?;
        Err(Error::ResponseError(ResponseContent {
            status,
            content,
            entity: None,
        }))
    }
}
