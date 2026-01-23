//! Integration Test Template
//!
//! Use this template when creating integration tests for crypto operations.
//! Integration tests should live in a `tests/` directory at the crate root.

#[cfg(feature = "internal")]
#[tokio::test]
async fn test_[operation_name]_complete_flow() {
    use bitwarden_core::{Client, /* other imports */};
    use bitwarden_crypto::{Kdf, /* other imports */};
    use std::num::NonZeroU32;

    // Step 1: Initialize client WITHOUT server connection
    // Most crypto tests don't need a server - they test SDK component integration
    let client = Client::new(None);

    let email = "test@bitwarden.com";
    let password = "secure_password";
    let kdf = Kdf::PBKDF2 {
        iterations: NonZeroU32::new(600_000).unwrap(),
    };

    // Step 2: Execute the primary operation
    let result = client
        .auth()
        .make_register_keys(email.to_owned(), password.to_owned(), kdf.clone())
        .unwrap();

    // Step 3: Verify the result
    assert!(result.master_password_hash.len() > 0, "Password hash should be generated");
    assert!(result.encrypted_user_key.len() > 0, "User key should be encrypted");

    // Step 4: Test dependent operations (e.g., initialize crypto after registration)
    client.crypto()
        .initialize_user_crypto(InitUserCryptoRequest {
            kdf_params: kdf,
            email: email.to_owned(),
            private_key: result.keys.private_key,
            method: InitUserCryptoMethod::Password {
                password: password.to_owned(),
                user_key: result.keys.encrypted_user_key,
            },
        })
        .await
        .unwrap();

    // Step 5: Verify complete state
    // Test that crypto initialization succeeded
    let user_key = client.crypto()
        .get_user_encryption_key()
        .await
        .unwrap();
    assert!(user_key.is_some(), "User encryption key should be available after initialization");
}

#[cfg(feature = "internal")]
#[tokio::test]
async fn test_[operation_name]_failure_case() {
    use bitwarden_core::Client;

    // Test error handling for invalid inputs
    let client = Client::new(None);

    let result = client
        .crypto()
        .initialize_user_crypto(/* invalid params */)
        .await;

    assert!(result.is_err(), "Should fail with invalid credentials");
}

// Example: Test with mocked API (only when API communication is needed)
#[cfg(feature = "internal")]
#[tokio::test]
async fn test_[operation_name]_with_api() {
    use bitwarden_test::start_api_mock;
    use wiremock::{Mock, ResponseTemplate, matchers};

    // Setup mock server responses
    let mock = Mock::given(matchers::method("POST"))
        .and(matchers::path("/api/accounts/register"))
        .respond_with(ResponseTemplate::new(200).set_body_json(/* response */));

    let (server, config) = start_api_mock(vec![mock]).await;
    let client = Client::new(Some(config));

    // Test operation that communicates with API
    let result = client.operation().execute().await.unwrap();

    assert!(result.is_ok());
    // server is automatically dropped and verifies all mocked endpoints were called
}
