use super::{SshKeyDataV1, SshKeyView};

impl_bidirectional_from!(
    SshKeyView,
    SshKeyDataV1,
    [private_key, public_key, fingerprint,]
);

#[cfg(test)]
mod tests {
    use super::super::{CipherBlobV1, test_support::*};
    use crate::cipher::{cipher::CipherType, ssh_key::SshKeyView};

    #[test]
    fn test_ssh_key_cipher_round_trip() {
        let (key_store, key_id) = create_test_key_store();
        let mut ctx = key_store.context_mut();

        let original = crate::CipherView {
            name: "My SSH Key".to_string(),
            notes: None,
            r#type: CipherType::SshKey,
            ssh_key: Some(SshKeyView {
                private_key: "-----BEGIN OPENSSH PRIVATE KEY-----".to_string(),
                public_key: "ssh-ed25519 AAAA".to_string(),
                fingerprint: "SHA256:abc123".to_string(),
            }),
            ..create_shell_cipher_view(CipherType::SshKey)
        };

        let blob = CipherBlobV1::from_cipher_view(&original, &mut ctx, key_id).unwrap();
        let mut restored = create_shell_cipher_view(CipherType::SshKey);
        blob.apply_to_cipher_view(&mut restored, &mut ctx, key_id)
            .unwrap();

        assert_eq!(restored.name, "My SSH Key");
        assert_eq!(restored.r#type, CipherType::SshKey);
        let ssh_key = restored.ssh_key.unwrap();
        assert_eq!(ssh_key.private_key, "-----BEGIN OPENSSH PRIVATE KEY-----");
        assert_eq!(ssh_key.public_key, "ssh-ed25519 AAAA");
        assert!(restored.login.is_none());
    }
}
