//! Error types for API operations.

/// An error returned by the API client.
#[derive(Debug, thiserror::Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum Error {
    /// Server returned an HTTP error response.
    #[error("API error {status}: {content}")]
    Response {
        /// HTTP status code of the response.
        status: reqwest::StatusCode,
        /// Raw response body content.
        content: String,
    },

    /// Could not reach the server (DNS failure, timeout, TLS error, connection refused, etc.)
    #[error("not connected: {0}")]
    NotConnected(String),

    /// Catch-all for other errors (serialization, IO, etc.)
    #[error("other error: {0}")]
    Other(String),
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        if let Some(status) = e.status() {
            return Error::Response {
                status,
                // Can't get the response body from a reqwest::Error, so just leave it empty.
                // The generated bindings create this error variant themselves so we shouldn't
                // enter this branch.
                content: String::new(),
            };
        }

        // is_connect() is only available on non-wasm targets
        #[cfg(target_arch = "wasm32")]
        let is_connect = false;
        #[cfg(not(target_arch = "wasm32"))]
        let is_connect = e.is_connect();

        // Consider connection errors, timeouts, and errors sending requests as "not connected",
        // since they all indicate a failure to communicate with the server.
        if is_connect || e.is_timeout() || e.is_request() {
            return Error::NotConnected(e.to_string());
        }

        Error::Other(e.to_string())
    }
}

impl From<reqwest_middleware::Error> for Error {
    fn from(e: reqwest_middleware::Error) -> Self {
        match e {
            reqwest_middleware::Error::Reqwest(e) => e.into(),
            reqwest_middleware::Error::Middleware(e) => Error::Other(e.to_string()),
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Other(e.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Other(e.to_string())
    }
}
