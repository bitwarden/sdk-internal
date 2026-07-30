#[test]
fn km_sync_user_decryption_is_nameable_downstream() {
    let _ = bitwarden_km_sync_handler::KmSyncData {
        user_decryption: Some(bitwarden_km_sync_handler::KmSyncUserDecryption::default()),
        ..Default::default()
    };
}
