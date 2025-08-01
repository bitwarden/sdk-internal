use bitwarden_ssh::import::import_der_key;
use bitwarden_vault::FieldType;
use credential_exchange_format::SshKeyCredential;

use crate::{cxf::editable_field::create_field, Field, SshKey};

pub(super) fn to_ssh(credential: &SshKeyCredential) -> (SshKey, Vec<Field>) {
    // Convert to OpenSSH format
    let encoded_key: Vec<u8> = credential.private_key.as_ref().into();
    let encoded_key = import_der_key(&encoded_key).expect("valid SSH key format");

    let ssh = SshKey {
        private_key: encoded_key.private_key,
        public_key: encoded_key.public_key,
        fingerprint: encoded_key.fingerprint,
    };

    let fields = [
        credential.key_comment.as_ref().map(|comment| Field {
            name: Some("Key Comment".into()),
            value: Some(comment.into()),
            r#type: FieldType::Text as u8,
            linked_id: None,
        }),
        credential
            .creation_date
            .as_ref()
            .map(|date| create_field("Creation Date", date)),
        credential
            .expiry_date
            .as_ref()
            .map(|date| create_field("Expiry Date", date)),
        credential
            .key_generation_source
            .as_ref()
            .map(|source| create_field("Key Generation Source", source)),
    ]
    .into_iter()
    .flatten()
    .collect();

    (ssh, fields)
}

#[cfg(test)]
mod tests {
    use bitwarden_vault::FieldType;
    use chrono::NaiveDate;
    use credential_exchange_format::EditableFieldDate;

    use super::*;

    #[test]
    fn test_to_ssh() {
        let credential = SshKeyCredential {
            key_type: "ssh-ed25519".into(),
            private_key: "MC4CAQAwBQYDK2VwBCIEID-U9VakauO4Fsv4b_znpDHcdYg74U68siZjnWLPn7Q1"
                .try_into()
                .unwrap(),
            key_comment: Some("Work SSH Key".into()),
            creation_date: Some(
                EditableFieldDate(NaiveDate::from_ymd_opt(2023, 1, 1).unwrap()).into(),
            ),
            expiry_date: Some(
                EditableFieldDate(NaiveDate::from_ymd_opt(2025, 1, 1).unwrap()).into(),
            ),
            key_generation_source: Some("Generated using OpenSSH".to_owned().into()),
        };

        let (ssh, fields) = to_ssh(&credential);

        assert_eq!(ssh.private_key, "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACDQiCIk4t4YPC6bOSb7CLzac/vC+ZudqhYqY00cxqr8zAAAAIilFVdupRVX\nbgAAAAtzc2gtZWQyNTUxOQAAACDQiCIk4t4YPC6bOSb7CLzac/vC+ZudqhYqY00cxqr8zA\nAAAEA/lPVWpGrjuBbL+G/856Qx3HWIO+FOvLImY51iz5+0NdCIIiTi3hg8Lps5JvsIvNpz\n+8L5m52qFipjTRzGqvzMAAAAAAECAwQF\n-----END OPENSSH PRIVATE KEY-----\n");
        assert_eq!(
            ssh.public_key,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINCIIiTi3hg8Lps5JvsIvNpz+8L5m52qFipjTRzGqvzM"
        );
        assert_eq!(
            ssh.fingerprint,
            "SHA256:mZ0BOhUVicE81yPEpFJrv1rEXB2R3Y3t5nh/riicTvs"
        );

        assert_eq!(fields.len(), 4);
        assert_eq!(
            fields[0],
            Field {
                name: Some("Key Comment".to_string()),
                value: Some("Work SSH Key".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            }
        );
        assert_eq!(fields[1].value.as_deref(), Some("2023-01-01"));
        assert_eq!(fields[2].value.as_deref(), Some("2025-01-01"));
        assert_eq!(fields[3].value.as_deref(), Some("Generated using OpenSSH"));
    }
}
