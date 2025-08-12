use bitwarden_ssh::{error::SshKeyImportError, import::import_pkcs8_der};
use bitwarden_vault::FieldType;
use credential_exchange_format::SshKeyCredential;

use crate::{cxf::editable_field::create_field, Field, SshKey};

/// Convert SSH key credentials to SshKey and custom fields
pub(super) fn to_ssh(
    credential: &SshKeyCredential,
) -> Result<(SshKey, Vec<Field>), SshKeyImportError> {
    // Convert to OpenSSH format
    let encoded_key: Vec<u8> = credential.private_key.as_ref().into();
    let encoded_key = import_pkcs8_der(&encoded_key)?;

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

    Ok((ssh, fields))
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
            private_key: "MIIG_QIBADANBgkqhkiG9w0BAQEFAASCBucwggbjAgEAAoIBgQCn4-QiJojZ9mgc9KYJIvDWGaz4qFhf0CButg6L8zEoHKwuiN-mqcEciCCOa9BNiJmm8NTTehZvrrglGG59zIbqYtDAHjVn-vtb49xPzIv-M651Yqj08lIbR9tEIHKCq7aH8GlDm8NgG9EzJGjlL7okQym4TH1MHl-s4mUyr_qb2unlZBDixAQsphU8iCLftukWCIkmQg4CSj1Gh3WbBlZ-EX5eW0EXuAw4XsSbBTWV9CHRowVIpYqPvEYSpHsoCjEcd988p19hpiGknA0J4z7JfUlNgyT_1chb8GCTDT-2DCBRApbsIg6TOBVS-PR6emAQ3eZzUW0-3_oRM4ip0ujltQy8uU6gvYIAqx5wXGMThVpZcUgahKiSsVo_s4b84iMe4DG3W8jz4qi6yyNv0VedEzPUZ1lXd1GJFoy9uKNuSTe-1ksicAcluZN6LuNsPHcPxFCzOcmoNnVXEKAXInt-ys__5CDVasroZSAHZnDjUD4oNsLI3VIOnGxgXrkwSH0CAwEAAQKCAYAA2SDMf7OBHw1OGM9OQa1ZS4u-ktfQHhn31-FxbrhWGp-lDt8gYABVf6Y4dKN6rMtn7D9gVSAlZCAn3Hx8aWAvcXHaspxe9YXiZDTh-Kd8EIXxBQn-TiDA5LH0dryABqmMp20vYKtR7OS3lIIXfFBSrBMwdunKzLwmKwZLWq0SWf6vVbwpxRyR9CyByodF6DjmZK3QB2qQ3jqlL1HWXL0VnyArY7HLvUvfLLK4vMPqnsSH-FdHvhcEhwqMlWT44g-fhqWtCJNnjDgLK3FPbI8Pz9TF8dWJvOmp5Q6iSBua1e9x2LizVuNSqiFc7ZTLeoG4nDj7T2BtqB0E1rNUDEN1aBo-UZmHJK7LrzfW_B-ssi2WwIpfxYa1lO6HFod5_YQiXV1GunyH1chCsbvOFtXvAHASO4HTKlJNbWhRF1GXqnKpAaHDPCVuwp3eq6Yf0oLbXrL3KFZ3jwWiWbpQXRVvpqzaJwZn3CN1yQgYS9j17a9wrPky-BoJxXjZ_oImWLECgcEA0lkLwiHvmTYFTCC7PN938Agk9_NQs5PQ18MRn9OJmyfSpYqf_gNp-Md7xUgtF_MTif7uelp2J7DYf6fj9EYf9g4EuW-SQgFP4pfiJn1-zGFeTQq1ISvwjsA4E8ZSt-GIumjZTg6YiL1_A79u4wm24swt7iqnVViOPtPGOM34S1tAamjZzq2eZDmAF6pAfmuTMdinCMR1E1kNJYbxeqLiqQCXuwBBnHOOOJofN3AkvzjRUBB9udvniqYxH3PQcxPxAoHBAMxT5KwBhZhnJedYN87Kkcpl7xdMkpU8b-aXeZoNykCeoC-wgIQexnSWmFk4HPkCNxvCWlbkOT1MHrTAKFnaOww23Ob-Vi6A9n0rozo9vtoJig114GB0gUqEmtfLhO1P5AE8yzogE-ILHyp0BqXt8vGIfzpDnCkN-GKl8gOOMPrR4NAcLO-Rshc5nLs7BGB4SEi126Y6mSfp85m0--1QhWMz9HzqJEHCWKVcZYdCdEONP9js04EUnK33KtlJIWzZTQKBwAT0pBpGwmZRp35Lpx2gBitZhcVxrg0NBnaO2fNyAGPvZD8SLQLHAdAiov_a23Uc_PDbWLL5Pp9gwzj-s5glrssVOXdE8aUscr1b5rARdNNL1_Tos6u8ZUZ3sNqGaZx7a8U4gyYboexWyo9EC1C-AdkGBm7-AkM4euFwC9N6xsa_t5zKK5d676hc0m-8SxivYCBkgkrqlfeGuZCQxU-mVsC0it6U-va8ojUjLGkZ80OuCwBf4xZl3-acU7vx9o8_gQKBwB7BrhU6MWrsc-cr_1KQaXum9mNyckomi82RFYvb8Yrilcg38FBy9XqNRKeBa9MLw1HZYpHbzsXsVF7u4eQMloDTLVNUC5L6dKAI1owoyTa24uH90WWTg_a8mTZMe1jhgrew-AJq27NV6z4PswR9GenDmyshDDudz7rBsflZCQRoXUfWRelV7BHU6UPBsXn4ASF4xnRyM6WvcKy9coKZcUqqgm3fLM_9OizCCMJgfXHBrE-x7nBqst746qlEedSRrQKBwQCVYwwKCHNlZxl0_NMkDJ-hp7_InHF6mz_3VO58iCb19TLDVUC2dDGPXNYwWTT9PclefwV5HNBHcAfTzgB4dpQyNiDyV914HL7DFEGduoPnwBYjeFre54v0YjjnskjJO7myircdbdX__i-7LMUw5aZZXCC8a5BD_rdV6IKJWJG5QBXbe5fVf1XwOjBTzlhIPIqhNFfSu-mFikp5BRwHGBqsKMju6inYmW6YADeY_SvOQjDEB37RqGZxqyIx8V2ZYwU"
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

        let (ssh, fields) = to_ssh(&credential).unwrap();

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
