//! Offline validation of [`ClientSettings`], for apps to run before storing them.

use bitwarden_error::bitwarden_error;
use thiserror::Error;

use super::{
    ClientCertificate, ClientCertificateError, ClientSettings,
    transport::{build_proxy, check_http_scheme},
};

/// An invalid field in [`ClientSettings`] or the client certificate. Messages never contain URLs
/// or credentials, so apps can log them.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum ValidateClientSettingsError {
    /// `identity_url` is not an `http` or `https` URL with a host.
    #[error("Invalid identity URL: {0}")]
    IdentityUrl(String),
    /// `api_url` is not an `http` or `https` URL with a host.
    #[error("Invalid API URL: {0}")]
    ApiUrl(String),
    /// The proxy URL is invalid or uses a scheme other than `http` or `https`.
    #[error("Invalid proxy URL: {0}")]
    ProxyUrl(String),
    /// `connect_ms` is 0.
    #[error("The connect timeout must be greater than 0")]
    ConnectTimeout,
    /// `read_ms` is 0.
    #[error("The read timeout must be greater than 0")]
    ReadTimeout,
    /// `request_ms` is 0.
    #[error("The request timeout must be greater than 0")]
    RequestTimeout,
    /// The client certificate cannot complete a TLS handshake.
    #[error("Invalid client certificate: {0}")]
    ClientCertificate(#[source] ClientCertificateError),
}

/// Checks `settings` for values the client would reject or ignore. The client constructor never
/// fails and only logs invalid settings, so apps call this before storing settings a user entered.
pub fn validate_client_settings(
    settings: &ClientSettings,
    client_certificate: Option<&ClientCertificate>,
) -> Result<(), ValidateClientSettingsError> {
    use ValidateClientSettingsError as E;

    check_server_url(&settings.identity_url).map_err(E::IdentityUrl)?;
    check_server_url(&settings.api_url).map_err(E::ApiUrl)?;
    if let Some(transport) = &settings.transport {
        if let Some(proxy) = &transport.proxy {
            build_proxy(proxy).map_err(E::ProxyUrl)?;
        }
        if let Some(timeouts) = &transport.timeouts {
            for (value, error) in [
                (timeouts.connect_ms, E::ConnectTimeout),
                (timeouts.read_ms, E::ReadTimeout),
                (timeouts.request_ms, E::RequestTimeout),
            ] {
                if value == Some(0) {
                    return Err(error);
                }
            }
        }
    }
    // Last, since it calls into the app's signer once per scheme.
    if let Some(certificate) = client_certificate {
        certificate.validate().map_err(E::ClientCertificate)?;
    }

    Ok(())
}

fn check_server_url(url: &str) -> Result<(), String> {
    let parsed = url::Url::parse(url).map_err(|error| error.to_string())?;
    check_http_scheme(&parsed)?;
    if parsed.host_str().is_none_or(str::is_empty) {
        return Err("missing host".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProxyCredentials, ProxySettings, TimeoutSettings, TransportSettings};

    fn validate(settings: &ClientSettings) -> Result<(), ValidateClientSettingsError> {
        validate_client_settings(settings, None)
    }

    fn settings_with_proxy(url: &str) -> ClientSettings {
        ClientSettings {
            transport: Some(TransportSettings {
                proxy: Some(ProxySettings {
                    url: url.to_owned(),
                    credentials: Some(ProxyCredentials {
                        username: "user".to_owned(),
                        password: "field-secret".to_owned(),
                    }),
                    no_proxy: None,
                }),
                timeouts: None,
            }),
            ..Default::default()
        }
    }

    fn settings_with_timeouts(timeouts: TimeoutSettings) -> ClientSettings {
        ClientSettings {
            transport: Some(TransportSettings {
                proxy: None,
                timeouts: Some(timeouts),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn accepts_valid_settings() {
        validate(&ClientSettings::default()).unwrap();

        let mut settings = settings_with_proxy("https://proxy.example.com:3128");
        settings.identity_url = "http://localhost:33656".to_owned();
        settings.api_url = "https://vault.example.com/api".to_owned();
        settings.transport.as_mut().unwrap().timeouts = Some(TimeoutSettings {
            connect_ms: Some(1),
            read_ms: Some(2),
            request_ms: None,
        });
        validate(&settings).unwrap();

        validate(&settings_with_proxy("proxy.example.com:3128")).unwrap();
    }

    #[test]
    fn rejects_invalid_server_urls() {
        for url in [
            "",
            "vault.example.com",
            "ftp://vault.example.com",
            "https://",
        ] {
            let settings = ClientSettings {
                identity_url: url.to_owned(),
                ..Default::default()
            };
            assert!(
                matches!(
                    validate(&settings),
                    Err(ValidateClientSettingsError::IdentityUrl(_))
                ),
                "{url}"
            );

            let settings = ClientSettings {
                api_url: url.to_owned(),
                ..Default::default()
            };
            assert!(
                matches!(
                    validate(&settings),
                    Err(ValidateClientSettingsError::ApiUrl(_))
                ),
                "{url}"
            );
        }
    }

    #[test]
    fn server_url_error_hides_userinfo() {
        let settings = ClientSettings {
            api_url: "ftp://user:url-secret@vault.example.com".to_owned(),
            ..Default::default()
        };

        let error = validate(&settings).unwrap_err();

        assert!(matches!(error, ValidateClientSettingsError::ApiUrl(_)));
        for text in [error.to_string(), format!("{error:?}")] {
            assert!(!text.contains("url-secret"), "{text}");
            assert!(!text.contains("user"), "{text}");
        }
    }

    #[test]
    fn rejects_invalid_proxy_urls_without_leaking_secrets() {
        for url in [
            "htps://user:url-secret@proxy.example.com:3128",
            "socks5://user:url-secret@proxy.example.com:1080",
            "http://user:url-secret@proxy.example.com:notaport",
        ] {
            let error = validate(&settings_with_proxy(url)).unwrap_err();

            assert!(
                matches!(error, ValidateClientSettingsError::ProxyUrl(_)),
                "{url}: {error:?}"
            );
            for text in [error.to_string(), format!("{error:?}")] {
                assert!(!text.contains("url-secret"), "{text}");
                assert!(!text.contains("field-secret"), "{text}");
            }
        }
    }

    #[test]
    fn rejects_zero_timeouts() {
        use ValidateClientSettingsError as E;

        let cases = [
            (
                TimeoutSettings {
                    connect_ms: Some(0),
                    ..Default::default()
                },
                E::ConnectTimeout,
            ),
            (
                TimeoutSettings {
                    read_ms: Some(0),
                    ..Default::default()
                },
                E::ReadTimeout,
            ),
            (
                TimeoutSettings {
                    request_ms: Some(0),
                    ..Default::default()
                },
                E::RequestTimeout,
            ),
        ];

        for (timeouts, expected) in cases {
            let error = validate(&settings_with_timeouts(timeouts.clone())).unwrap_err();
            assert_eq!(
                std::mem::discriminant(&error),
                std::mem::discriminant(&expected),
                "{timeouts:?}: {error:?}"
            );
        }
    }

    #[test]
    fn rejects_an_invalid_client_certificate() {
        struct NoSigner;

        impl crate::ClientCertSigner for NoSigner {
            fn sign(
                &self,
                _scheme: crate::TlsSigScheme,
                _message: Vec<u8>,
            ) -> Result<Vec<u8>, crate::ClientCertSignerError> {
                unreachable!("an empty chain fails before signing")
            }

            fn schemes(&self) -> Vec<crate::TlsSigScheme> {
                vec![]
            }
        }

        let certificate = ClientCertificate::new(vec![], std::sync::Arc::new(NoSigner));
        let error = validate_client_settings(&ClientSettings::default(), Some(&certificate));

        assert!(matches!(
            error,
            Err(ValidateClientSettingsError::ClientCertificate(
                ClientCertificateError::EmptyChain
            ))
        ));
    }
}
