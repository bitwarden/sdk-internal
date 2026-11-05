//! Rotation outcomes against a live server.

use std::time::Duration;

use bitwarden_access_connector::executor::RunExit;
use bitwarden_test::play::{Play, play_test};

use super::{
    cipher::read_login,
    fixture::RotationFixture,
    runner::run_until_resolved,
    scenes::enums::{attempt_action, job_action},
};

/// The custom script rotates, verify passes, and the vault ends up holding what the script was
/// given.
#[cfg(unix)]
#[play_test]
async fn rotation_succeeds_and_the_vault_holds_the_new_password(play: Play) {
    let fixture = RotationFixture::builder().seed(&play).await;
    let before = read_login(
        &play,
        fixture.organization_id,
        &fixture.org_key,
        fixture.cipher_id,
    )
    .await;
    assert_eq!(before.password, fixture.initial_password);
    assert!(before.key.is_some(), "the cipher has an item key");

    let out_dir = tempfile::tempdir().expect("tempdir");
    let out_path = out_dir.path().join("out");
    let env = fixture.script_env("record_and_exit.sh", &out_path, &[]);

    let outcome = run_until_resolved(
        &play,
        fixture.connector.token(),
        fixture.job_id,
        &env,
        None,
        Duration::from_secs(60),
    )
    .await;

    assert!(outcome.resolved, "no attempt resolved: {:?}", outcome.job);
    assert_eq!(outcome.exit, RunExit::Shutdown);
    assert_eq!(outcome.job.action, job_action::SUCCEEDED);
    assert_eq!(outcome.job.attempts.len(), 1);
    let attempt = &outcome.job.attempts[0];
    assert_eq!(attempt.action, attempt_action::ROTATED);
    assert!(attempt.cipher_updated);
    assert_eq!(attempt.failure_reason, None);
    assert_eq!(
        attempt.claimed_by_access_connector_id,
        fixture.connector.access_connector_id
    );
    assert!(outcome.job.last_rotation_date.is_some());

    let read_payload = |operation: &str| -> serde_json::Value {
        let path = format!("{}.{operation}", out_path.display());
        let body = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("the {operation} script did not run ({path}): {e}"));
        serde_json::from_str(&body).expect("payload is JSON")
    };
    let rotate = read_payload("rotate");
    let verify = read_payload("verify");
    assert_eq!(rotate["operation"], "rotate");
    assert_eq!(verify["operation"], "verify");
    assert_eq!(rotate["accountIdentity"], fixture.account_identity.as_str());
    assert_eq!(
        rotate["targetSystemId"],
        fixture.target_system_id.to_string().as_str()
    );
    let new_password = rotate["newPassword"]
        .as_str()
        .expect("rotate got a password");
    assert_eq!(verify["newPassword"], new_password);

    let after = read_login(
        &play,
        fixture.organization_id,
        &fixture.org_key,
        fixture.cipher_id,
    )
    .await;
    assert_eq!(after.password, new_password);
    assert_ne!(after.password, fixture.initial_password);
    assert_eq!(
        after.password_history.first(),
        Some(&fixture.initial_password)
    );
    assert_eq!(after.key, before.key, "the item key is unchanged");
    assert!(after.password_revision_date.is_some());
    let length = u32::try_from(new_password.chars().count()).expect("length fits");
    assert!(
        (fixture.password_policy.min_length..=fixture.password_policy.max_length).contains(&length),
        "password length {length} is outside the sealed policy"
    );
}
