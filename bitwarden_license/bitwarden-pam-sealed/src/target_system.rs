use bitwarden_crypto::{
    KeySlotIds, KeyStoreContext, generate_versioned_sealable,
    safe::{DataEnvelopeNamespace, SealableData, SealableVersionedData},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    container::{SealedContainer, SealedDataError},
    policy::SealedPasswordPolicy,
};

/// Whether a target's credentials are rotated automatically or by hand.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SealedTargetSystemMethod {
    /// Rotated by the connector on a schedule.
    Automatic,
    /// The connector never dispatches jobs for this target.
    Manual,
}

/// Connector plugin that rotates an automatic target.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SealedTargetSystemKind {
    /// Microsoft Entra ID.
    Entra,
    /// Microsoft SQL Server.
    Mssql,
    /// A customer-supplied rotation script.
    CustomScript,
}

/// Security-relevant fields of a PAM target system. Sealed so neither a hostile server nor a MitM
/// can change its kind, password policy, or session-termination support.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TargetSystemSealedV1 {
    /// Cross-checked against the claim and the rotation config's copy to stop blob swaps.
    pub target_system_id: Uuid,
    /// The connector requires this to be `Automatic` before running a job.
    pub method: SealedTargetSystemMethod,
    /// `None` for manual targets.
    pub kind: Option<SealedTargetSystemKind>,
    /// Policy for the generated credential.
    pub password_policy: SealedPasswordPolicy,
    /// `None` for manual targets.
    pub supports_session_termination: Option<bool>,
}
impl SealableData for TargetSystemSealedV1 {}

generate_versioned_sealable!(
    TargetSystemSealed,
    DataEnvelopeNamespace::PamTargetSystem,
    [
        TargetSystemSealedV1 => "1",
    ]
);

/// Seals `data` into an opaque string under `org_key`.
pub fn seal_target_system<Ids: KeySlotIds>(
    data: TargetSystemSealedV1,
    org_key: &Ids::Symmetric,
    ctx: &mut KeyStoreContext<Ids>,
) -> Result<String, SealedDataError> {
    let versioned: TargetSystemSealed = data.into();
    SealedContainer::seal(versioned, org_key, ctx)?.to_opaque_string()
}

/// Unseals a [`TargetSystemSealedV1`] from a string produced by [`seal_target_system`].
pub fn unseal_target_system<Ids: KeySlotIds>(
    blob: &str,
    org_key: &Ids::Symmetric,
    ctx: &mut KeyStoreContext<Ids>,
) -> Result<TargetSystemSealedV1, SealedDataError> {
    let container = SealedContainer::from_opaque_string(blob)?;
    let versioned: TargetSystemSealed = container.unseal(org_key, ctx)?;
    let TargetSystemSealed::TargetSystemSealedV1(data) = versioned;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use bitwarden_crypto::{KeyStore, SymmetricCryptoKey, safe::DataEnvelopeError};
    use bitwarden_encoding::B64;

    use super::*;
    use crate::{
        container::SealedDataError, rotation_config::unseal_rotation_config, test_support::TestIds,
    };

    fn sample() -> TargetSystemSealedV1 {
        TargetSystemSealedV1 {
            target_system_id: Uuid::parse_str("8c6e7d1a-3e3f-4a5b-9c1d-2f3e4d5c6b7a").unwrap(),
            method: SealedTargetSystemMethod::Automatic,
            kind: Some(SealedTargetSystemKind::Entra),
            password_policy: SealedPasswordPolicy {
                min_length: 20,
                max_length: 20,
                include_uppercase: true,
                include_lowercase: true,
                include_digits: true,
                include_symbols: true,
            },
            supports_session_termination: Some(true),
        }
    }

    #[test]
    fn round_trip() {
        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();
        let org_key = ctx.generate_symmetric_key();

        let data = sample();
        let blob = seal_target_system(data.clone(), &org_key, &mut ctx).unwrap();
        let unsealed = unseal_target_system(&blob, &org_key, &mut ctx).unwrap();

        assert_eq!(unsealed, data);
    }

    #[test]
    fn opaque_string_round_trip() {
        // Simulates round-tripping through storage: reparsing must not change what unseals.
        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();
        let org_key = ctx.generate_symmetric_key();

        let data = sample();
        let blob = seal_target_system(data.clone(), &org_key, &mut ctx).unwrap();
        let blob_from_storage = String::from(blob.as_str());

        let unsealed = unseal_target_system(&blob_from_storage, &org_key, &mut ctx).unwrap();
        assert_eq!(unsealed, data);
    }

    #[test]
    fn unsupported_format_version_is_rejected() {
        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();
        let org_key = ctx.generate_symmetric_key();

        let blob = seal_target_system(sample(), &org_key, &mut ctx).unwrap();
        let tampered = blob.replacen("\"format_version\":1", "\"format_version\":99", 1);
        assert_ne!(blob, tampered, "fixture JSON shape must contain the key");

        let result = unseal_target_system::<TestIds>(&tampered, &org_key, &mut ctx);
        assert!(matches!(
            result,
            Err(SealedDataError::UnsupportedFormatVersion(99))
        ));
    }

    #[test]
    fn wrong_key_fails() {
        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();
        let org_key = ctx.generate_symmetric_key();
        let wrong_key = ctx.generate_symmetric_key();

        let blob = seal_target_system(sample(), &org_key, &mut ctx).unwrap();
        let result = unseal_target_system::<TestIds>(&blob, &wrong_key, &mut ctx);

        assert!(matches!(
            result,
            Err(SealedDataError::DataEnvelope(_)) | Err(SealedDataError::JsonDecoding)
        ));
    }

    #[test]
    fn target_system_blob_cannot_be_unsealed_as_rotation_config() {
        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();
        let org_key = ctx.generate_symmetric_key();

        let blob = seal_target_system(sample(), &org_key, &mut ctx).unwrap();
        let result = unseal_rotation_config::<TestIds>(&blob, &org_key, &mut ctx);

        assert!(matches!(
            result,
            Err(SealedDataError::DataEnvelope(
                DataEnvelopeError::InvalidNamespace
            ))
        ));
    }

    #[test]
    #[ignore = "Manual test to generate test vectors"]
    fn generate_test_vectors() {
        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();
        let org_key = ctx.generate_symmetric_key();
        let key_b64 = {
            #[allow(deprecated)]
            let key = ctx.dangerous_get_symmetric_key(org_key).unwrap();
            key.to_base64()
        };

        let blob = seal_target_system(sample(), &org_key, &mut ctx).unwrap();

        println!("const TEST_VECTOR_ORG_KEY: &str = \"{key_b64}\";");
        println!("const TEST_VECTOR_TARGET_SYSTEM_BLOB: &str = r#\"{blob}\"#;");
    }

    const TEST_VECTOR_ORG_KEY: &str =
        "MUgcMToL6hTXhQSr3bQuvJDw+P4y9vlRlvEQ36yFlgErQ0kdL5Xh3U92i/P3uJVk7X6ujV/uWO9usbo/X+0YcA==";
    const TEST_VECTOR_TARGET_SYSTEM_BLOB: &str = r#"{"format_version":1,"wrapped_cek":"2.WakihY9ZIyZBuvrrvELJiQ==|j4sTuFZ7BqvcHiGKGcuI2tTjf3sZv29iUvh/I0eO/3EHzCuxsrEajOdZOneS9w1Hyag8agcO2IjmEOc0t3baBSpFqqZrmy/5UJ99n/zE3gU=|+DDgtyBastM+rPThuzq2ec4xa1ejGZMJaijzwf7aK9w=","envelope":"g1hHpQEDA3gjYXBwbGljYXRpb24veC5iaXR3YXJkZW4uY2Jvci1wYWRkZWQEUHRhqF0LBJ8L12LJH4jFX186AAE4gQI6AAE4gAShBUxjXNBlDL/mPqel7U1Y8r2jmj4RoevZ2EkAV+RTDBLzvGAH6a0YBM8wm9G72AK+rpeVpLrQrFnAimeptb+OJj0Y5Wd2aC5ZZaRfeAzISQeSOGSk6M6Hfdn3YZR0RiJXbggAAc+rs0Zi7zSbfzffpmAfLxGuNG8tCEgInq8KijZnK1p8ff6uCEcNMhstzt5uFC3R1Mm/ua+iNiaYqXAZZLGn1vKQ8f4IC2G61SYtmgN70iZjea4HCad48Lrp16ny1/OAxAsR9iJgMTOHVDGXrAerGBKcJiho0My6CwVPQmQNHgNN1Ki/gvflT1FiYWFkiHat09pOfgGoDyjc3X8dbcgy"}"#;

    #[test]
    fn target_system_test_vector() {
        let org_key =
            SymmetricCryptoKey::try_from(B64::try_from(TEST_VECTOR_ORG_KEY).unwrap()).unwrap();

        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();
        let org_key_id = ctx.add_local_symmetric_key(org_key);

        let unsealed = unseal_target_system(TEST_VECTOR_TARGET_SYSTEM_BLOB, &org_key_id, &mut ctx)
            .expect(
                "TargetSystemSealed wire format has changed in a backwards-incompatible way. \
                 Existing sealed data must remain deserializable.",
            );

        assert_eq!(unsealed, sample());
    }
}
