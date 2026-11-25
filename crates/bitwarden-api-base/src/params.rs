//! Builder methods for generated bindings: parameters of any serializable type, so the bindings
//! don't branch on the parameter's shape, and sending the request.

use std::future::Future;

use reqwest::multipart::Form;
use reqwest_middleware::RequestBuilder;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

use crate::{Error, process_with_empty_response, process_with_json_response};

/// Request builder methods for the generated API bindings.
pub trait RequestBuilderExt: Sized {
    /// Adds `name=value`, or nothing for `None`. Arrays add one pair per item. Objects are an
    /// error.
    fn with_query<T: Serialize + ?Sized>(self, name: &str, value: &T) -> Result<Self, Error>;

    /// Sets the header `name`, or nothing for `None`. Arrays are joined with commas.
    fn with_header<T: Serialize + ?Sized>(self, name: &str, value: &T) -> Result<Self, Error>;

    /// Sends the request and deserializes the JSON response. See [`process_with_json_response`].
    fn send_json<T: DeserializeOwned>(self) -> impl Future<Output = Result<T, Error>>;

    /// Sends the request and expects no response body. See [`process_with_empty_response`].
    fn send_empty(self) -> impl Future<Output = Result<(), Error>>;
}

impl RequestBuilderExt for RequestBuilder {
    fn with_query<T: Serialize + ?Sized>(self, name: &str, value: &T) -> Result<Self, Error> {
        let pairs: Vec<(String, String)> = match serde_json::to_value(value)? {
            Value::Null => return Ok(self),
            Value::Array(items) => items
                .into_iter()
                .filter(|item| !item.is_null())
                .map(|item| (name.to_owned(), plain(item)))
                .collect(),
            Value::Object(_) => {
                return Err(<serde_json::Error as serde::ser::Error>::custom(format!(
                    "query parameter '{name}' is an object"
                ))
                .into());
            }
            scalar => vec![(name.to_owned(), plain(scalar))],
        };
        Ok(self.query(&pairs))
    }

    fn with_header<T: Serialize + ?Sized>(self, name: &str, value: &T) -> Result<Self, Error> {
        Ok(match joined(value)? {
            Some(value) => self.header(name, value),
            None => self,
        })
    }

    fn send_json<T: DeserializeOwned>(self) -> impl Future<Output = Result<T, Error>> {
        process_with_json_response(self)
    }

    fn send_empty(self) -> impl Future<Output = Result<(), Error>> {
        process_with_empty_response(self)
    }
}

/// Adds text fields to a multipart form.
pub trait FormExt: Sized {
    /// Adds the text field `name`, or nothing for `None`. Arrays are joined with commas.
    fn with_text<T: Serialize + ?Sized>(self, name: &str, value: &T) -> Result<Self, Error>;
}

impl FormExt for Form {
    fn with_text<T: Serialize + ?Sized>(self, name: &str, value: &T) -> Result<Self, Error> {
        Ok(match joined(value)? {
            Some(value) => self.text(name.to_owned(), value),
            None => self,
        })
    }
}

/// The value as one string, with array items joined by commas, or `None` for `null`.
fn joined<T: Serialize + ?Sized>(value: &T) -> Result<Option<String>, Error> {
    Ok(match serde_json::to_value(value)? {
        Value::Null => None,
        Value::Array(items) => Some(items.into_iter().map(plain).collect::<Vec<_>>().join(",")),
        other => Some(plain(other)),
    })
}

/// Strings without their JSON quotes, everything else as JSON.
fn plain(value: Value) -> String {
    match value {
        Value::String(s) => s,
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use serde::Serialize;

    use super::*;

    fn request() -> RequestBuilder {
        reqwest_middleware::ClientBuilder::new(crate::new_http_client())
            .build()
            .get("https://example.com/path")
    }

    fn query_of(build: impl FnOnce(RequestBuilder) -> Result<RequestBuilder, Error>) -> String {
        let request = build(request()).unwrap().build().unwrap();
        request.url().query().unwrap_or_default().to_owned()
    }

    #[derive(Serialize)]
    enum Kind {
        #[serde(rename = "public-key")]
        PublicKey,
    }

    #[derive(Serialize)]
    struct Filter {
        id: u32,
    }

    #[test]
    fn with_query_skips_none() {
        assert_eq!(query_of(|r| r.with_query("a", &None::<&str>)), "");
    }

    #[test]
    fn with_query_adds_scalars_without_quotes() {
        let query = query_of(|r| {
            r.with_query("s", "a b")?
                .with_query("b", &true)?
                .with_query("i", &42)?
                .with_query("o", &Some(7))?
                .with_query("e", &Kind::PublicKey)
        });
        assert_eq!(query, "s=a+b&b=true&i=42&o=7&e=public-key");
    }

    #[test]
    fn with_query_repeats_the_name_for_arrays() {
        assert_eq!(
            query_of(|r| r.with_query("id", &vec!["x", "y"])),
            "id=x&id=y"
        );
    }

    #[test]
    fn with_query_rejects_objects() {
        let filter = Filter { id: 1 };
        assert!(request().with_query("filter", &filter).is_err());
    }

    #[test]
    fn with_header_joins_arrays_and_skips_none() {
        let request = request()
            .with_header("x-list", &vec![1, 2])
            .unwrap()
            .with_header("x-none", &None::<String>)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(request.headers()["x-list"], "1,2");
        assert!(request.headers().get("x-none").is_none());
    }
}
