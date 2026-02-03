//! Utility functions for API operations.

/// URL-encodes a string for use in query parameters.
pub fn urlencode<T: AsRef<str>>(s: T) -> String {
    url::form_urlencoded::byte_serialize(s.as_ref().as_bytes()).collect()
}

/// Marker struct used for endpoints that require authentication.
/// It will be included in the request's extensions to signal to the middleware
/// that authentication is required.
#[derive(Debug, Clone, Copy)]
pub enum AuthRequired {
    /// Basic authentication.
    Basic,
    /// Bearer token authentication.
    Bearer,
    /// Custom header authentication.
    Header(&'static str),
}

/// Content types supported by the API client.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ContentType {
    /// JSON content (application/json).
    Json,
    /// Plain text content.
    Text,
    /// Unsupported content type.
    Unsupported(String),
}

impl From<&str> for ContentType {
    fn from(content_type: &str) -> Self {
        if content_type.starts_with("application") && content_type.contains("json") {
            Self::Json
        } else if content_type.starts_with("text/plain") {
            Self::Text
        } else {
            Self::Unsupported(content_type.to_string())
        }
    }
}

/// Parses a deep object (nested JSON) into flat query parameters.
///
/// This is used for serializing complex query parameters in the OpenAPI
/// "deepObject" style.
pub fn parse_deep_object(prefix: &str, value: &serde_json::Value) -> Vec<(String, String)> {
    if let serde_json::Value::Object(object) = value {
        let mut params = vec![];

        for (key, value) in object {
            match value {
                serde_json::Value::Object(_) => params.append(&mut parse_deep_object(
                    &format!("{}[{}]", prefix, key),
                    value,
                )),
                serde_json::Value::Array(array) => {
                    for (i, value) in array.iter().enumerate() {
                        params.append(&mut parse_deep_object(
                            &format!("{}[{}][{}]", prefix, key, i),
                            value,
                        ));
                    }
                }
                serde_json::Value::String(s) => {
                    params.push((format!("{}[{}]", prefix, key), s.clone()));
                }
                _ => params.push((format!("{}[{}]", prefix, key), value.to_string())),
            }
        }

        return params;
    }

    unimplemented!("Only objects are supported with style=deepObject")
}
