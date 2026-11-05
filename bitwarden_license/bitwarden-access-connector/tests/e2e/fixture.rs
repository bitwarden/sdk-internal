//! Seeds a complete rotation scenario: user, PAM organization, connector and its token, a sealed
//! target system, an assignment, a keyed login cipher, a sealed rotation config and a job.

use std::path::{Path, PathBuf};

use bitwarden_access_token::{AccessToken, AccessTokenKind, make_access_token_secrets};
use bitwarden_core::{
    OrganizationId,
    key_management::{KeySlotIds, SymmetricKeySlotId},
};
use bitwarden_crypto::{KeyStore, SymmetricCryptoKey};
use bitwarden_encoding::B64;
use bitwarden_pam_sealed::{
    RotationConfigSealedV1, Sealed, SealedPasswordPolicy, SealedTargetSystemKind,
    SealedTargetSystemMethod, TargetSystemSealedV1,
};
use bitwarden_test::play::{
    OrganizationLoginCipherArgs, OrganizationLoginCipherScene, OrganizationOverrides, PlanType,
    Play, SingleOrganizationArgs, SingleOrganizationScene, SingleUserArgs, SingleUserScene,
};
use uuid::Uuid;

use super::scenes::{
    OrganizationAccessConnectorArgs, OrganizationAccessConnectorScene,
    PamAccessConnectorTargetAssignmentArgs, PamAccessConnectorTargetAssignmentScene,
    PamRotationConfigArgs, PamRotationConfigScene, PamRotationConfigUpdateArgs,
    PamRotationConfigUpdateScene, PamRotationJobArgs, PamRotationJobScene, PamTargetSystemArgs,
    PamTargetSystemScene, PamTargetSystemSealArgs, PamTargetSystemSealScene,
    enums::{connector_status, target_status},
};
use crate::common::{env_prefix, fixtures_dir, seal_config_blob, seal_target_blob};

/// The vault password a freshly seeded cipher holds.
pub const INITIAL_PASSWORD: &str = "old-password";

/// The account identity sealed into the rotation config unless a test overrides it.
pub const DEFAULT_ACCOUNT_IDENTITY: &str = "e2e-account@example.com";

/// A seeded access connector and the token that authenticates as it.
#[derive(Debug, Clone)]
pub struct ConnectorCredential {
    pub access_connector_id: Uuid,
    pub api_key_id: Uuid,
    token: String,
}

impl ConnectorCredential {
    /// The token string, for a process that parses it itself (`BWAC_TOKEN`).
    pub fn token_string(&self) -> &str {
        &self.token
    }

    /// The parsed access token, `0.access-connector.{apiKeyId}.{clientSecret}:{encKeyB64}`.
    pub fn token(&self) -> AccessToken {
        AccessToken::parse(&self.token, AccessTokenKind::AccessConnector)
            .expect("assembled token parses")
    }
}

/// Everything seeded for one rotation scenario. Ids are the server's; names inside the scenes are
/// mangled by the Play framework.
pub struct RotationFixture {
    pub user_id: Uuid,
    pub organization_id: Uuid,
    pub org_key: SymmetricCryptoKey,
    pub org_key_b64: String,
    /// The connector assigned to the target.
    pub connector: ConnectorCredential,
    pub target_system_id: Uuid,
    pub cipher_id: Uuid,
    pub rotation_config_id: Uuid,
    pub job_id: Uuid,
    /// The password policy sealed into the target system.
    pub password_policy: SealedPasswordPolicy,
    pub initial_password: String,
    pub account_identity: String,
    /// The per-target environment variable prefix, ending in `_`.
    pub env_prefix: String,
    target_sealed: Sealed,
}

/// Knobs for [`RotationFixture`]; each defaults to the happy path.
pub struct RotationFixtureBuilder {
    use_pam: bool,
    connector_status: i32,
    assign_connector: bool,
    use_cipher_key: bool,
    tamper_config_cipher_id: bool,
    terminate_sessions: bool,
    account_identity: String,
    job_expires_in_seconds: Option<i32>,
}

impl RotationFixture {
    pub fn builder() -> RotationFixtureBuilder {
        RotationFixtureBuilder {
            use_pam: true,
            connector_status: connector_status::ENABLED,
            assign_connector: true,
            use_cipher_key: true,
            tamper_config_cipher_id: false,
            terminate_sessions: false,
            account_identity: DEFAULT_ACCOUNT_IDENTITY.to_owned(),
            job_expires_in_seconds: None,
        }
    }

    /// The directory holding the fixture scripts.
    pub fn script_path(name: &str) -> PathBuf {
        fixtures_dir().join(name)
    }

    /// Per-target credentials for the connector's environment: each `(name, value)` becomes
    /// `{prefix}{name}`. Pass `SCRIPT` to select the script.
    pub fn env(&self, vars: &[(&str, &str)]) -> Vec<(String, String)> {
        vars.iter()
            .map(|(name, value)| (format!("{}{name}", self.env_prefix), (*value).to_owned()))
            .collect()
    }

    /// The environment for `script` under `fixtures/`, recording its payloads to `out_path`.
    pub fn script_env(
        &self,
        script: &str,
        out_path: &Path,
        extra: &[(&str, &str)],
    ) -> Vec<(String, String)> {
        let script = Self::script_path(script);
        let mut vars = vec![
            ("SCRIPT", script.to_str().expect("utf8 path")),
            ("OUT_PATH", out_path.to_str().expect("utf8 path")),
        ];
        vars.extend_from_slice(extra);
        self.env(&vars)
    }

    /// Seeds a second connector, assigns it to the same target and returns its credential.
    pub async fn add_connector(&self, play: &Play) -> ConnectorCredential {
        let connector = seed_connector(
            play,
            self.organization_id,
            &self.org_key,
            "second connector",
            connector_status::ENABLED,
        )
        .await;
        seed_assignment(
            play,
            self.organization_id,
            connector.access_connector_id,
            self.target_system_id,
        )
        .await;
        connector
    }

    /// Disables the rotation config after its job was seeded.
    pub async fn disable_config(&self, play: &Play) {
        play.scene::<PamRotationConfigUpdateScene>(&PamRotationConfigUpdateArgs {
            rotation_config_id: self.rotation_config_id,
            enabled: false,
        })
        .await
        .expect("PamRotationConfigUpdateScene");
    }

    /// Disables the target system after the job was seeded.
    pub async fn disable_target(&self, play: &Play) {
        seal_target(
            play,
            self.target_system_id,
            &self.target_sealed,
            target_status::DISABLED,
        )
        .await;
    }
}

impl RotationFixtureBuilder {
    /// Whether the organization has `UsePam` (default true).
    pub fn use_pam(mut self, use_pam: bool) -> Self {
        self.use_pam = use_pam;
        self
    }

    /// The connector's status (default enabled); see [`connector_status`].
    pub fn connector_status(mut self, status: i32) -> Self {
        self.connector_status = status;
        self
    }

    /// Whether the connector is assigned to the target (default true).
    pub fn assign_connector(mut self, assign: bool) -> Self {
        self.assign_connector = assign;
        self
    }

    /// Whether the cipher has an item key (default true).
    pub fn use_cipher_key(mut self, use_cipher_key: bool) -> Self {
        self.use_cipher_key = use_cipher_key;
        self
    }

    /// Seals the rotation config with a cipher id other than the job's cipher.
    pub fn tamper_config_cipher_id(mut self, tamper: bool) -> Self {
        self.tamper_config_cipher_id = tamper;
        self
    }

    /// Whether the config asks for sessions to be terminated (default false). The target always
    /// declares support for it.
    pub fn terminate_sessions(mut self, terminate: bool) -> Self {
        self.terminate_sessions = terminate;
        self
    }

    /// The sealed account identity.
    pub fn account_identity(mut self, identity: impl Into<String>) -> Self {
        self.account_identity = identity.into();
        self
    }

    /// Seconds until the job expires; negative seeds an expired job (default: the seeder's).
    pub fn job_expires_in_seconds(mut self, seconds: i32) -> Self {
        self.job_expires_in_seconds = Some(seconds);
        self
    }

    /// Seeds everything, panicking on any failure so a misseeded test fails at setup.
    pub async fn seed(self, play: &Play) -> RotationFixture {
        let unique: String = Uuid::new_v4()
            .simple()
            .to_string()
            .chars()
            .take(12)
            .collect();

        let user = play
            .scene::<SingleUserScene>(&SingleUserArgs {
                email: format!("e2e-pam-{unique}@bitwarden.test"),
                password: "asdfasdfasdf".to_owned(),
                email_verified: true,
                ..Default::default()
            })
            .await
            .expect("SingleUserScene");
        let user_id = user.result().user_id;

        let org = play
            .scene::<SingleOrganizationScene>(&SingleOrganizationArgs {
                owner_user_id: user_id,
                plan_type: PlanType::ENTERPRISE_ANNUALLY,
                name: format!("e2e-pam-{unique}"),
                domain: format!("e2e-pam-{unique}.example.com"),
                seats: 5,
                overrides: Some(OrganizationOverrides {
                    use_pam: Some(self.use_pam),
                }),
            })
            .await
            .expect("SingleOrganizationScene");
        let organization_id = org.result().organization_id;
        let org_key_b64 = org.result().organization_key_b64.clone();
        let org_key = SymmetricCryptoKey::try_from(
            org_key_b64
                .parse::<B64>()
                .expect("organization key is base64"),
        )
        .expect("organization key decodes");

        let connector = seed_connector(
            play,
            organization_id,
            &org_key,
            "connector",
            self.connector_status,
        )
        .await;

        let target_system_id = play
            .scene::<PamTargetSystemScene>(&PamTargetSystemArgs {
                organization_id,
                name: "e2e target".to_owned(),
                method: None,
            })
            .await
            .expect("PamTargetSystemScene")
            .result()
            .target_system_id;

        let password_policy = SealedPasswordPolicy {
            min_length: 12,
            max_length: 24,
            include_uppercase: true,
            include_lowercase: true,
            include_digits: true,
            include_symbols: true,
        };
        let target_sealed = seal_target_blob(
            &org_key,
            TargetSystemSealedV1 {
                target_system_id,
                method: SealedTargetSystemMethod::Automatic,
                kind: Some(SealedTargetSystemKind::CustomScript),
                password_policy: password_policy.clone(),
                supports_session_termination: Some(true),
            },
        );
        seal_target(
            play,
            target_system_id,
            &target_sealed,
            target_status::ACTIVE,
        )
        .await;

        if self.assign_connector {
            seed_assignment(
                play,
                organization_id,
                connector.access_connector_id,
                target_system_id,
            )
            .await;
        }

        let cipher_id = play
            .scene::<OrganizationLoginCipherScene>(&OrganizationLoginCipherArgs {
                user_id,
                organization_id,
                organization_key_b64: org_key_b64.clone(),
                collection_ids: Vec::new(),
                name: "e2e rotated login".to_owned(),
                username: Some(self.account_identity.clone()),
                password: Some(INITIAL_PASSWORD.to_owned()),
                uri: None,
                use_cipher_key: Some(self.use_cipher_key),
            })
            .await
            .expect("OrganizationLoginCipherScene")
            .result()
            .cipher_id;

        let config_sealed = seal_config_blob(
            &org_key,
            RotationConfigSealedV1 {
                target_system_id,
                cipher_id: if self.tamper_config_cipher_id {
                    Uuid::new_v4()
                } else {
                    cipher_id
                },
                account_identity: self.account_identity.clone(),
                terminate_sessions: self.terminate_sessions,
            },
        );
        let rotation_config_id = play
            .scene::<PamRotationConfigScene>(&PamRotationConfigArgs {
                organization_id,
                cipher_id,
                target_system_id,
                sealed_data: config_sealed.envelope.to_string(),
                wrapped_key: config_sealed.wrapped_key.to_string(),
                enabled: None,
            })
            .await
            .expect("PamRotationConfigScene")
            .result()
            .rotation_config_id;

        let job_id = play
            .scene::<PamRotationJobScene>(&PamRotationJobArgs {
                rotation_config_id,
                expires_in_seconds: self.job_expires_in_seconds,
                next_claimable_in_seconds: None,
            })
            .await
            .expect("PamRotationJobScene")
            .result()
            .job_id;

        RotationFixture {
            user_id,
            organization_id,
            org_key,
            org_key_b64,
            connector,
            target_system_id,
            cipher_id,
            rotation_config_id,
            job_id,
            password_policy,
            initial_password: INITIAL_PASSWORD.to_owned(),
            account_identity: self.account_identity,
            env_prefix: env_prefix(target_system_id),
            target_sealed,
        }
    }
}

/// Registers a connector whose token is minted under `org_key`.
async fn seed_connector(
    play: &Play,
    organization_id: Uuid,
    org_key: &SymmetricCryptoKey,
    name: &str,
    status: i32,
) -> ConnectorCredential {
    let org_slot = SymmetricKeySlotId::Organization(OrganizationId::new(organization_id));
    let store = KeyStore::<KeySlotIds>::default();
    #[allow(deprecated)]
    store
        .context_mut()
        .set_symmetric_key(org_slot, org_key.clone())
        .expect("set_symmetric_key");
    let secrets = make_access_token_secrets(
        &mut store.context_mut(),
        org_slot,
        AccessTokenKind::AccessConnector,
    )
    .expect("mint access token secrets");

    let scene = play
        .scene::<OrganizationAccessConnectorScene>(&OrganizationAccessConnectorArgs {
            organization_id,
            name: name.to_owned(),
            encrypted_payload: secrets.encrypted_payload.to_string(),
            key: secrets.key.to_string(),
            status: Some(status),
        })
        .await
        .expect("OrganizationAccessConnectorScene");
    let result = scene.result();

    ConnectorCredential {
        access_connector_id: result.access_connector_id,
        api_key_id: result.api_key_id,
        token: secrets.into_token(result.api_key_id, &result.client_secret),
    }
}

async fn seed_assignment(
    play: &Play,
    organization_id: Uuid,
    access_connector_id: Uuid,
    target_system_id: Uuid,
) {
    play.scene::<PamAccessConnectorTargetAssignmentScene>(
        &PamAccessConnectorTargetAssignmentArgs {
            organization_id,
            access_connector_id,
            target_system_id,
        },
    )
    .await
    .expect("PamAccessConnectorTargetAssignmentScene");
}

async fn seal_target(play: &Play, target_system_id: Uuid, sealed: &Sealed, status: i32) {
    play.scene::<PamTargetSystemSealScene>(&PamTargetSystemSealArgs {
        target_system_id,
        sealed_data: sealed.envelope.to_string(),
        wrapped_key: sealed.wrapped_key.to_string(),
        status: Some(status),
    })
    .await
    .expect("PamTargetSystemSealScene");
}
