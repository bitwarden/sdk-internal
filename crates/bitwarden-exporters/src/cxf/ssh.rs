use bitwarden_ssh::{error::SshKeyImportError, import::import_pkcs8_der_key};
use bitwarden_vault::FieldType;
use credential_exchange_format::SshKeyCredential;

use crate::{cxf::editable_field::create_field, Field, SshKey};

/// Convert SSH key credentials to SshKey and custom fields
pub(super) fn to_ssh(
    credential: &SshKeyCredential,
) -> Result<(SshKey, Vec<Field>), SshKeyImportError> {
    // Convert to OpenSSH format
    let encoded_key: Vec<u8> = credential.private_key.as_ref().into();
    let encoded_key = import_pkcs8_der_key(&encoded_key)?;

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

        assert_eq!(ssh.private_key, "-----BEGIN OPENSSH PRIVATE KEY-----\n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\nScrfcq2UkhbNlNAAAAAAEC\n-----END OPENSSH PRIVATE KEY-----\n");
        assert_eq!(
            ssh.public_key,
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCn4+QiJojZ9mgc9KYJIvDWGaz4qFhf0CButg6L8zEoHKwuiN+mqcEciCCOa9BNiJmm8NTTehZvrrglGG59zIbqYtDAHjVn+vtb49xPzIv+M651Yqj08lIbR9tEIHKCq7aH8GlDm8NgG9EzJGjlL7okQym4TH1MHl+s4mUyr/qb2unlZBDixAQsphU8iCLftukWCIkmQg4CSj1Gh3WbBlZ+EX5eW0EXuAw4XsSbBTWV9CHRowVIpYqPvEYSpHsoCjEcd988p19hpiGknA0J4z7JfUlNgyT/1chb8GCTDT+2DCBRApbsIg6TOBVS+PR6emAQ3eZzUW0+3/oRM4ip0ujltQy8uU6gvYIAqx5wXGMThVpZcUgahKiSsVo/s4b84iMe4DG3W8jz4qi6yyNv0VedEzPUZ1lXd1GJFoy9uKNuSTe+1ksicAcluZN6LuNsPHcPxFCzOcmoNnVXEKAXInt+ys//5CDVasroZSAHZnDjUD4oNsLI3VIOnGxgXrkwSH0="
        );
        assert_eq!(
            ssh.fingerprint,
            "SHA256:vWqZh87vgxDk0eDx0VqWR001mXyFGTdRF4Q2JVW/Q9w"
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
