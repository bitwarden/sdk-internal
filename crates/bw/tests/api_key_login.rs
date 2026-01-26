//! E2E test for API key login using the Play test framework

use bitwarden_test::play::{Play, SingleUserArgs, SingleUserScene};

mod common;
use common::bw;

/// Test API key login flow using the Play framework
///
/// This test:
/// 1. Creates a test user via the seeder API
/// 2. Retrieves API key credentials
/// 3. Performs API key login via the bw CLI
/// 4. Verifies authentication succeeds
/// 5. Automatically cleans up the test user when play is dropped
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[ignore = "Integration test requires running Bitwarden server with seeder API"]
async fn test_api_key_login() {
    let play = Play::new();

    let args = SingleUserArgs {
        email: "e2e-apikey@bitwarden.test".to_string(),
        verified: true,
        id: Some("378538f1-2426-4788-87c5-df39a78618c1".parse().unwrap()),
        api_key: Some("api_key".to_string()),
        ..Default::default()
    };

    let server = common::server_base();

    let scene = play
        .scene::<SingleUserScene>(&args)
        .await
        .expect("Failed to create SingleUserScene");

    // Build credentials from the mangled scene data
    let client_id = format!(
        "user.{}",
        scene
            .get_mangled("378538f1-2426-4788-87c5-df39a78618c1")
            .unwrap()
    );
    let client_secret = scene.get_mangled("api_key").unwrap();

    let output = bw()
        .args(["login", "api-key", &client_id, client_secret])
        .args(["--server", &server])
        .env("BW_PASSWORD", "asdfasdfasdf")
        .output()
        .expect("Failed to execute bw command");

    assert!(
        output.status.success(),
        "CLI login failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Test API key login with invalid credentials fails appropriately
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[ignore = "Integration test requires running Bitwarden server with seeder API"]
async fn test_api_key_login_invalid_credentials() {
    let _play = Play::new();

    let server = common::server_base();

    let output = bw()
        .args(["login", "api-key", "invalid_client_id", "invalid_secret"])
        .args(["--server", &server])
        .env("BW_PASSWORD", "wrong_password")
        .output()
        .expect("Failed to execute bw command");

    assert!(
        !output.status.success(),
        "Login with invalid credentials should fail"
    );
}
