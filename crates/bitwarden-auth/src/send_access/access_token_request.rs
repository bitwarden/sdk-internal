#[cfg(feature = "wasm")]
use tsify::Tsify;

/// Credentials for sending password secured access requests.
/// Clone auto implements the standard lib's Clone trait, allowing us to create copies of this
/// struct.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct SendPasswordCredentials {
    /// A Base64-encoded hash of the password protecting the send.
    pub password_hash_b64: String,
}

/// Credentials for sending an OTP to the user's email address.
/// This is used when the send requires email verification with an OTP.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct SendEmailCredentials {
    /// The email address to which the OTP will be sent.
    pub email: String,
}

/// Credentials for getting a send access token using an email and OTP.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct SendEmailOtpCredentials {
    /// The email address to which the OTP will be sent.
    pub email: String,
    /// The one-time password (OTP) that the user has received via email.
    pub otp: String,
}

/// The credentials used for send access requests.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
// Use untagged so that each variant can be serialized without a type tag.
// For example, this allows us to serialize the password credentials as just
// {"password_hash_b64": "value"} instead of {"type": "password", "password_hash_b64": "value"}.
#[serde(untagged)]
pub enum SendAccessCredentials {
    #[allow(missing_docs)]
    Password(SendPasswordCredentials),
    // IMPORTANT: EmailOtp must come before Email due to #[serde(untagged)] deserialization.
    // Serde tries variants in order and stops at the first match. Since EmailOtp has
    // both "email" and "otp" fields, while Email only has "email", placing Email first
    // would cause {"email": "...", "otp": "..."} to incorrectly match the Email variant
    // (ignoring the "otp" field). We always must order untagged enum variants from most specific
    // (most fields) to least specific (fewest fields).
    #[allow(missing_docs)]
    EmailOtp(SendEmailOtpCredentials),
    #[allow(missing_docs)]
    Email(SendEmailCredentials),
}

/// A request structure for requesting a send access token from the API.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct SendAccessTokenRequest {
    /// The id of the send for which the access token is requested.
    pub send_id: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "wasm", tsify(optional))]
    /// The optional send access credentials.
    pub send_access_credentials: Option<SendAccessCredentials>,
}

#[cfg(test)]
mod tests {
    use super::*;

    mod send_access_token_request_tests {
        use serde_json::{from_str, to_string};

        use super::*;

        #[test]
        fn deserialize_camelcase_request() {
            let json = r#"
        {
          "sendId": "abc123",
          "sendAccessCredentials": { "passwordHashB64": "ha$h" }
        }"#;

            let req: SendAccessTokenRequest = from_str(json).unwrap();
            assert_eq!(req.send_id, "abc123");

            let creds = req.send_access_credentials.expect("expected Some");
            match creds {
                SendAccessCredentials::Password(p) => assert_eq!(p.password_hash_b64, "ha$h"),
                _ => panic!("expected Password variant"),
            }
        }

        #[test]
        fn serialize_camelcase_request_with_credentials() {
            let req = SendAccessTokenRequest {
                send_id: "abc123".into(),
                send_access_credentials: Some(SendAccessCredentials::Password(
                    SendPasswordCredentials {
                        password_hash_b64: "ha$h".into(),
                    },
                )),
            };
            let json = to_string(&req).unwrap();
            assert_eq!(
                json,
                r#"{"sendId":"abc123","sendAccessCredentials":{"passwordHashB64":"ha$h"}}"#
            );
        }

        #[test]
        fn serialize_omits_optional_credentials_when_none() {
            let req = SendAccessTokenRequest {
                send_id: "abc123".into(),
                send_access_credentials: None,
            };
            let json = to_string(&req).unwrap();
            assert_eq!(json, r#"{"sendId":"abc123"}"#);
        }

        #[test]
        fn roundtrip_camel_in_to_camel_out() {
            let in_json = r#"
        {
          "sendId": "abc123",
          "sendAccessCredentials": { "passwordHashB64": "ha$h" }
        }"#;

            let req: SendAccessTokenRequest = from_str(in_json).unwrap();
            let out_json = to_string(&req).unwrap();
            assert_eq!(
                out_json,
                r#"{"sendId":"abc123","sendAccessCredentials":{"passwordHashB64":"ha$h"}}"#
            );
        }

        #[test]
        fn snakecase_top_level_keys_are_rejected() {
            let json = r#"
        {
          "send_id": "abc123",
          "sendAccessCredentials": { "passwordHashB64": "ha$h" }
        }"#;
            let err = from_str::<SendAccessTokenRequest>(json).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("unknown field") && msg.contains("send_id"),
                "unexpected: {msg}"
            );
        }

        #[test]
        fn extra_top_level_key_is_rejected() {
            let json = r#"
        {
          "sendId": "abc123",
          "sendAccessCredentials": { "passwordHashB64": "ha$h" },
          "extra": "nope"
        }"#;
            let err = from_str::<SendAccessTokenRequest>(json).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("unknown field") && msg.contains("extra"),
                "unexpected: {msg}"
            );
        }

        #[test]
        fn snakecase_nested_keys_are_rejected() {
            let json = r#"
    {
      "sendId": "abc123",
      "sendAccessCredentials": { "password_hash_b64": "ha$h" }
    }"#;

            let err = serde_json::from_str::<SendAccessTokenRequest>(json).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("did not match any variant"),
                "unexpected: {msg}"
            );
        }

        #[test]
        fn extra_nested_key_is_rejected() {
            let json = r#"
        {
          "sendId": "abc123",
          "sendAccessCredentials": {
            "passwordHashB64": "ha$h",
            "extra": "nope"
          }
        }"#;
            let err = from_str::<SendAccessTokenRequest>(json).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("did not match any variant"),
                "unexpected: {msg}"
            );
        }
    }

    mod send_access_credentials_tests {
        use super::*;

        mod send_access_password_credentials_tests {
            use serde_json::{from_str, to_string};

            use super::*;

            #[test]
            fn deserialize_struct_camelcase_from_ts() {
                let json = r#"{ "passwordHashB64": "ha$h" }"#;
                let s: SendPasswordCredentials = from_str(json).unwrap();
                assert_eq!(s.password_hash_b64, "ha$h");
            }

            #[test]
            fn serialize_struct_camelcase_to_wire() {
                let s = SendPasswordCredentials {
                    password_hash_b64: "ha$h".into(),
                };
                let json = to_string(&s).unwrap();
                assert_eq!(json, r#"{"passwordHashB64":"ha$h"}"#);
            }

            #[test]
            fn roundtrip_struct_camel_in_to_camel_out() {
                let in_json = r#"{ "passwordHashB64": "ha$h" }"#;
                let parsed: SendPasswordCredentials = from_str(in_json).unwrap();
                let out_json = to_string(&parsed).unwrap();
                assert_eq!(out_json, r#"{"passwordHashB64":"ha$h"}"#);
            }

            #[test]
            fn deserialize_enum_variant_from_json() {
                let json = r#"{"passwordHashB64":"ha$h"}"#;
                let creds: SendAccessCredentials = from_str(json).unwrap();
                match creds {
                    SendAccessCredentials::Password(password_creds) => {
                        assert_eq!(password_creds.password_hash_b64, "ha$h");
                    }
                    _ => panic!("Expected Password variant"),
                }
            }

            #[test]
            fn serialize_enum_variant_to_json() {
                let creds = SendAccessCredentials::Password(SendPasswordCredentials {
                    password_hash_b64: "ha$h".into(),
                });
                let json = to_string(&creds).unwrap();
                assert_eq!(json, r#"{"passwordHashB64":"ha$h"}"#);
            }

            #[test]
            fn roundtrip_enum_variant_through_json() {
                let in_json = r#"{"passwordHashB64":"ha$h"}"#;
                let creds: SendAccessCredentials = from_str(in_json).unwrap();
                let out_json = to_string(&creds).unwrap();
                assert_eq!(out_json, r#"{"passwordHashB64":"ha$h"}"#);
            }
        }

        mod send_access_email_credentials_tests {
            use serde_json::{from_str, to_string};

            use super::*;

            #[test]
            fn deserialize_struct_camelcase_from_ts() {
                let json = r#"{ "email": "user@example.com" }"#;
                let s: SendEmailCredentials = from_str(json).unwrap();
                assert_eq!(s.email, "user@example.com");
            }

            #[test]
            fn serialize_struct_camelcase_to_wire() {
                let s = SendEmailCredentials {
                    email: "user@example.com".into(),
                };
                let json = to_string(&s).unwrap();
                assert_eq!(json, r#"{"email":"user@example.com"}"#);
            }

            #[test]
            fn roundtrip_struct_camel_in_to_camel_out() {
                let in_json = r#"{ "email": "user@example.com" }"#;
                let parsed: SendEmailCredentials = from_str(in_json).unwrap();
                let out_json = to_string(&parsed).unwrap();
                assert_eq!(out_json, r#"{"email":"user@example.com"}"#);
            }

            #[test]
            fn deserialize_enum_variant_from_json() {
                let json = r#"{"email":"user@example.com"}"#;
                let creds: SendAccessCredentials = from_str(json).unwrap();
                match creds {
                    SendAccessCredentials::Email(email_creds) => {
                        assert_eq!(email_creds.email, "user@example.com");
                    }
                    _ => panic!("Expected Email variant"),
                }
            }

            #[test]
            fn serialize_enum_variant_to_json() {
                let creds = SendAccessCredentials::Email(SendEmailCredentials {
                    email: "user@example.com".into(),
                });
                let json = to_string(&creds).unwrap();
                assert_eq!(json, r#"{"email":"user@example.com"}"#);
            }

            #[test]
            fn roundtrip_enum_variant_through_json() {
                let in_json = r#"{"email":"user@example.com"}"#;
                let creds: SendAccessCredentials = from_str(in_json).unwrap();
                let out_json = to_string(&creds).unwrap();
                assert_eq!(out_json, r#"{"email":"user@example.com"}"#);
            }
        }

        mod send_access_email_otp_credentials_tests {
            use serde_json::{from_str, to_string};

            use super::*;

            #[test]
            fn deserialize_struct_camelcase_from_ts() {
                let json = r#"{ "email": "user@example.com", "otp": "123456" }"#;
                let s: SendEmailOtpCredentials = from_str(json).unwrap();
                assert_eq!(s.email, "user@example.com");
                assert_eq!(s.otp, "123456");
            }

            #[test]
            fn serialize_struct_camelcase_to_wire() {
                let s = SendEmailOtpCredentials {
                    email: "user@example.com".into(),
                    otp: "123456".into(),
                };
                let json = to_string(&s).unwrap();
                assert_eq!(json, r#"{"email":"user@example.com","otp":"123456"}"#);
            }

            #[test]
            fn roundtrip_struct_camel_in_to_camel_out() {
                let in_json = r#"{ "email": "user@example.com", "otp": "123456" }"#;
                let parsed: SendEmailOtpCredentials = from_str(in_json).unwrap();
                let out_json = to_string(&parsed).unwrap();
                assert_eq!(out_json, r#"{"email":"user@example.com","otp":"123456"}"#);
            }

            #[test]
            fn deserialize_enum_variant_from_json() {
                let json = r#"{"email":"user@example.com","otp":"123456"}"#;
                let creds: SendAccessCredentials = from_str(json).unwrap();
                match creds {
                    SendAccessCredentials::EmailOtp(otp_creds) => {
                        assert_eq!(otp_creds.email, "user@example.com");
                        assert_eq!(otp_creds.otp, "123456");
                    }
                    _ => panic!("Expected EmailOtp variant"),
                }
            }

            #[test]
            fn serialize_enum_variant_to_json() {
                let creds = SendAccessCredentials::EmailOtp(SendEmailOtpCredentials {
                    email: "user@example.com".into(),
                    otp: "123456".into(),
                });
                let json = to_string(&creds).unwrap();
                assert_eq!(json, r#"{"email":"user@example.com","otp":"123456"}"#);
            }

            #[test]
            fn roundtrip_enum_variant_through_json() {
                let in_json = r#"{"email":"user@example.com","otp":"123456"}"#;
                let creds: SendAccessCredentials = from_str(in_json).unwrap();
                let out_json = to_string(&creds).unwrap();
                assert_eq!(out_json, r#"{"email":"user@example.com","otp":"123456"}"#);
            }
        }
    }
}
