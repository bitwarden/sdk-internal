//! Integration tests for the registration process

use bitwarden_test::MemoryRepository;

/// Integration test for registering a new user and unlocking the vault
#[cfg(feature = "internal")]
#[tokio::test]
async fn test_register_initialize_crypto() {
    use std::num::NonZeroU32;

    use bitwarden_core::{
        Client, UserId,
        key_management::{
            MasterPasswordUnlockData, UserKeyState,
            account_cryptographic_state::WrappedAccountCryptographicState,
            crypto::{InitUserCryptoMethod, InitUserCryptoRequest},
        },
    };
    use bitwarden_crypto::Kdf;

    let client = Client::new(None);

    let repository = MemoryRepository::<UserKeyState>::default();
    client
        .platform()
        .state()
        .register_client_managed(std::sync::Arc::new(repository));

    let email = "test@bitwarden.com";
    let password = "test123";
    let kdf = Kdf::PBKDF2 {
        iterations: NonZeroU32::new(600_000).unwrap(),
    };

    let register_response = client
        .auth()
        .make_register_keys(email.to_owned(), password.to_owned(), kdf.clone())
        .unwrap();

    // Ensure we can initialize the crypto with the new keys
    client
        .crypto()
        .initialize_user_crypto(InitUserCryptoRequest {
            user_id: Some(UserId::new_v4()),
            kdf_params: kdf.clone(),
            email: email.to_owned(),
            account_cryptographic_state: WrappedAccountCryptographicState::V1 {
                private_key: register_response.keys.private,
            },
            method: InitUserCryptoMethod::MasterPasswordUnlock {
                password: password.to_owned(),
                master_password_unlock: MasterPasswordUnlockData {
                    kdf,
                    master_key_wrapped_user_key: register_response.encrypted_user_key,
                    salt: email.to_owned(),
                },
            },
            upgrade_token: None,
        })
        .await
        .unwrap();
}
