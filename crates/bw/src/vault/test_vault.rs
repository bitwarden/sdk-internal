//! In-memory, fully isolated vault fixture for command tests.
//!
//! Each [`TestVault`] owns a fresh test-account client (real crypto, no network, no disk) and its
//! own in-memory cipher/folder repositories, so tests never share state and can run in parallel.

use std::sync::{Arc, Once};

use bitwarden_core::{
    Client, DeviceType, GlobalClient, HostPlatformInfo, client::test_accounts,
    init_host_platform_info,
};
use bitwarden_pm::PasswordManagerClient;
use bitwarden_test::MemoryRepository;
use bitwarden_vault::{Cipher, CipherId, CipherView, Folder, FolderView};
use serde_json::{Value, json};

use crate::client_state::{ClientContext, Unlocked};

static INIT: Once = Once::new();

fn ensure_platform_info() {
    INIT.call_once(|| {
        init_host_platform_info(HostPlatformInfo {
            user_agent: "bw-tests".to_string(),
            device_type: DeviceType::SDK,
            device_identifier: None,
            bitwarden_client_version: None,
            bitwarden_package_type: None,
        });
    });
}

pub struct TestVault {
    pub user: PasswordManagerClient,
    ciphers: Arc<MemoryRepository<Cipher>>,
    folders: Arc<MemoryRepository<Folder>>,
}

impl TestVault {
    /// A freshly unlocked, empty vault.
    pub async fn new() -> Self {
        ensure_platform_info();
        let client = Client::init_test_account(test_accounts::test_bitwarden_com_account()).await;

        let ciphers = Arc::new(MemoryRepository::<Cipher>::default());
        let folders = Arc::new(MemoryRepository::<Folder>::default());
        let state = client.platform().state();
        state.register_client_managed(ciphers.clone());
        state.register_client_managed(folders.clone());

        Self {
            user: PasswordManagerClient(client),
            ciphers,
            folders,
        }
    }

    pub fn unlocked(&self) -> Unlocked {
        Unlocked {
            global: GlobalClient::new(),
            user: self.user.clone(),
        }
    }

    pub fn context(&self) -> ClientContext {
        ClientContext {
            global: GlobalClient::new(),
            user: Some(self.user.clone()),
        }
    }

    /// Encrypt and store a cipher built from the given JSON (camelCase `CipherView` fields).
    pub async fn add_cipher(&self, id: &str, name: &str, extra: Value) -> CipherId {
        let mut view = json!({
            "id": id,
            "collectionIds": [],
            "name": name,
            "type": 1,
            "favorite": false,
            "reprompt": 0,
            "organizationUseTotp": false,
            "edit": true,
            "viewPassword": true,
            "creationDate": "2025-01-01T00:00:00Z",
            "revisionDate": "2025-01-01T00:00:00Z",
        });
        view.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let view: CipherView = serde_json::from_value(view).unwrap();

        let cipher = self
            .user
            .vault()
            .ciphers()
            .encrypt(view)
            .await
            .unwrap()
            .cipher;
        let id = cipher.id.unwrap();
        bitwarden_state::repository::Repository::set(self.ciphers.as_ref(), id, cipher)
            .await
            .unwrap();
        id
    }

    pub async fn add_login(&self, id: &str, name: &str, login: Value) -> CipherId {
        self.add_cipher(id, name, json!({ "login": login })).await
    }

    pub async fn trash(&self, id: &str, name: &str, login: Value) {
        self.add_cipher(
            id,
            name,
            json!({ "login": login, "deletedDate": "2025-02-01T00:00:00Z" }),
        )
        .await;
    }

    pub async fn add_folder(&self, id: &str, name: &str) {
        let view = FolderView {
            id: Some(id.parse().unwrap()),
            name: name.into(),
            revision_date: "2025-01-01T00:00:00Z".parse().unwrap(),
        };
        let folder: Folder = self.user.0.internal.get_key_store().encrypt(view).unwrap();
        bitwarden_state::repository::Repository::set(
            self.folders.as_ref(),
            folder.id.unwrap(),
            folder,
        )
        .await
        .unwrap();
    }
}
