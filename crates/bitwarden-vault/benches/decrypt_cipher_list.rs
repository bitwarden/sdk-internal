//! Time of the cipher list decrypts for ciphers passed from Rust, which is the path UniFFI
//! callers take. Run with `cargo bench -p bitwarden-vault --bench decrypt_cipher_list`; criterion
//! compares each run with the previous one, or with a baseline saved with `--save-baseline`.

#![allow(missing_docs, clippy::unwrap_used)]

use bitwarden_core::{Client, client::test_accounts::test_bitwarden_com_account};
use bitwarden_vault::{
    Cipher, CipherRepromptType, CipherType, Login, LoginUriView, UriMatchType, VaultClientExt,
};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};

const CIPHERS: usize = 12000;

/// A cipher of the test account, encrypted from a login with a username, a password, a URI and a
/// note, so each decrypt does about as much work as for a typical login.
async fn login_cipher(client: &Client) -> Cipher {
    let ciphers = client.vault().ciphers();
    let mut view = ciphers.decrypt(name_only_cipher()).await.unwrap();
    view.notes = Some("A note that is a few words long.".to_owned());
    let login = view.login.as_mut().unwrap();
    login.username = Some("user@example.com".to_owned());
    login.password = Some("correct horse battery staple".to_owned());
    login.uris = Some(vec![LoginUriView {
        uri: Some("https://vault.example.com/login".to_owned()),
        r#match: Some(UriMatchType::Domain),
        uri_checksum: None,
    }]);
    ciphers.encrypt(view).await.unwrap().cipher
}

/// A login of the test account with only a name.
fn name_only_cipher() -> Cipher {
    Cipher {
        partial_data: None,
        id: Some("358f2b2b-9326-4e5e-94a8-b18100bb0908".parse().unwrap()),
        organization_id: None,
        folder_id: None,
        collection_ids: vec![],
        key: None,
        name: Some("2.+oPT8B4xJhyhQRe1VkIx0A==|PBtC/bZkggXR+fSnL/pG7g==|UkjRD0VpnUYkjRC/05ZLdEBAmRbr3qWRyJey2bUvR9w=".parse().unwrap()),
        notes: None,
        r#type: CipherType::Login,
        login: Some(Login {
            username: None,
            password: None,
            password_revision_date: None,
            uris: None,
            totp: None,
            autofill_on_page_load: None,
            http_authentication_enabled: None,
            fido2_credentials: None,
        }),
        identity: None,
        card: None,
        secure_note: None,
        ssh_key: None,
        bank_account: None,
        drivers_license: None,
        passport: None,
        favorite: false,
        reprompt: CipherRepromptType::None,
        organization_use_totp: true,
        edit: true,
        permissions: None,
        view_password: true,
        local_data: None,
        attachments: None,
        fields: None,
        password_history: None,
        creation_date: "2024-05-31T11:20:58.4566667Z".parse().unwrap(),
        deleted_date: None,
        revision_date: "2024-05-31T11:20:58.4566667Z".parse().unwrap(),
        archived_date: None,
        data: None,
    }
}

fn decrypt_cipher_list(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let client = runtime.block_on(Client::init_test_account(test_bitwarden_com_account()));
    let cipher = runtime.block_on(login_cipher(&client));
    let ciphers = vec![cipher; CIPHERS];
    let client = client.vault().ciphers();

    let mut group = c.benchmark_group(format!("decrypt {CIPHERS} ciphers from Rust"));
    group.sample_size(30);
    group.bench_function("decrypt_list", |b| {
        b.iter_batched(
            || ciphers.clone(),
            |ciphers| {
                runtime
                    .block_on(client.decrypt_list(ciphers.into()))
                    .unwrap()
            },
            BatchSize::LargeInput,
        )
    });
    group.bench_function("decrypt_list_with_failures", |b| {
        b.iter_batched(
            || ciphers.clone(),
            |ciphers| {
                runtime
                    .block_on(client.decrypt_list_with_failures(ciphers.into()))
                    .unwrap()
            },
            BatchSize::LargeInput,
        )
    });
    group.bench_function("decrypt_list_full_with_failures", |b| {
        b.iter_batched(
            || ciphers.clone(),
            |ciphers| {
                runtime
                    .block_on(client.decrypt_list_full_with_failures(ciphers.into()))
                    .unwrap()
            },
            BatchSize::LargeInput,
        )
    });
    group.finish();
}

criterion_group!(benches, decrypt_cipher_list);
criterion_main!(benches);
