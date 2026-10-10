//! The CLI learning its leader's lock state, which it needs to report whether a shared session
//! with the desktop app is established:
//!
//! ```text
//! cli
//!  |
//! desktop
//! ```

use crate::prelude::*;

/// The CLI is told its leader's state, both when it is locked and when it is unlocked
///
/// ```text
/// cli     LOCKED --told Locked--> LOCKED --told Unlocked--> UNLOCKED
///  |
/// desktop LOCKED ---------------> UNLOCKED
/// ```
#[tokio::test]
async fn cli_is_told_peer_state() {
    let user = test_user(TestUserId::A);
    let topology = SharedUnlockTopology::new(fast_timing());
    let desktop = topology.add_device(
        "desktop",
        DeviceOptions::new(ClientType::Desktop, &[user.id]),
    );
    let cli = topology.add_device(
        "cli",
        DeviceOptions::new(ClientType::Cli, &[user.id]).following(&desktop),
    );
    topology.start().await;

    // 1. Both locked. A locked leader answering a locked CLI changes nothing, but the CLI must
    //    still be told, so it can tell "leader is locked" from "no leader answered".
    wait_for_peer_state(&topology, cli.name(), user.id, PeerLockState::Locked).await;
    assert_user_state(TargetLockState::Locked, &topology, &user);

    // 2. Unlock the desktop; the CLI must be told it is unlocked, and become unlocked.
    desktop.manual_unlock(user.id, &user.key).await;
    wait_for_peer_state(&topology, cli.name(), user.id, PeerLockState::Unlocked).await;
    wait_for_devices_reaching_state(TargetLockState::Unlocked, &topology, &user).await;
}
