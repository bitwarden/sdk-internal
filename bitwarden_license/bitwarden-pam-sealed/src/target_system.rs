use bitwarden_crypto::{
    EncString, KeySlotIds, KeyStoreContext, generate_versioned_sealable,
    safe::{
        DataEnvelope, DataEnvelopeError, DataEnvelopeNamespace, SealableData, SealableVersionedData,
    },
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{Sealed, policy::SealedPasswordPolicy};

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
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

/// Seals `data` under `org_key`.
pub fn seal_target_system<Ids: KeySlotIds>(
    data: TargetSystemSealedV1,
    org_key: &Ids::Symmetric,
    ctx: &mut KeyStoreContext<Ids>,
) -> Result<Sealed, DataEnvelopeError> {
    let versioned: TargetSystemSealed = data.into();
    let (envelope, wrapped_key) = DataEnvelope::seal_with_wrapping_key(versioned, org_key, ctx)?;
    Ok(Sealed {
        envelope,
        wrapped_key,
    })
}

/// Unseals a [`TargetSystemSealedV1`] from the output of [`seal_target_system`].
pub fn unseal_target_system<Ids: KeySlotIds>(
    envelope: &DataEnvelope,
    wrapped_key: &EncString,
    org_key: &Ids::Symmetric,
    ctx: &mut KeyStoreContext<Ids>,
) -> Result<TargetSystemSealedV1, DataEnvelopeError> {
    let versioned: TargetSystemSealed =
        envelope.unseal_with_wrapping_key(org_key, wrapped_key, ctx)?;
    let TargetSystemSealed::TargetSystemSealedV1(data) = versioned;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitwarden_crypto::{KeyStore, SymmetricCryptoKey, safe::DataEnvelopeError};
    use bitwarden_encoding::B64;

    use super::*;
    use crate::{rotation_config::unseal_rotation_config, test_support::TestIds};

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
        let Sealed {
            envelope,
            wrapped_key,
        } = seal_target_system(data.clone(), &org_key, &mut ctx).unwrap();
        let unsealed = unseal_target_system(&envelope, &wrapped_key, &org_key, &mut ctx).unwrap();

        assert_eq!(unsealed, data);
    }

    #[test]
    fn wire_string_round_trip() {
        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();
        let org_key = ctx.generate_symmetric_key();

        let data = sample();
        let Sealed {
            envelope,
            wrapped_key,
        } = seal_target_system(data.clone(), &org_key, &mut ctx).unwrap();
        let envelope: DataEnvelope = envelope.to_string().parse().unwrap();
        let wrapped_key: EncString = wrapped_key.to_string().parse().unwrap();

        let unsealed = unseal_target_system(&envelope, &wrapped_key, &org_key, &mut ctx).unwrap();
        assert_eq!(unsealed, data);
    }

    #[test]
    fn wrong_key_fails() {
        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();
        let org_key = ctx.generate_symmetric_key();
        let wrong_key = ctx.generate_symmetric_key();

        let Sealed {
            envelope,
            wrapped_key,
        } = seal_target_system(sample(), &org_key, &mut ctx).unwrap();
        let result = unseal_target_system::<TestIds>(&envelope, &wrapped_key, &wrong_key, &mut ctx);

        assert!(result.is_err());
    }

    #[test]
    fn target_system_blob_cannot_be_unsealed_as_rotation_config() {
        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();
        let org_key = ctx.generate_symmetric_key();

        let Sealed {
            envelope,
            wrapped_key,
        } = seal_target_system(sample(), &org_key, &mut ctx).unwrap();
        let result = unseal_rotation_config::<TestIds>(&envelope, &wrapped_key, &org_key, &mut ctx);

        assert!(matches!(result, Err(DataEnvelopeError::InvalidNamespace)));
    }

    #[test]
    fn swapped_wrapped_key_fails() {
        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();
        let org_key = ctx.generate_symmetric_key();

        let Sealed { envelope, .. } = seal_target_system(sample(), &org_key, &mut ctx).unwrap();
        let Sealed {
            wrapped_key: other_wrapped_key,
            ..
        } = seal_target_system(sample(), &org_key, &mut ctx).unwrap();
        let result =
            unseal_target_system::<TestIds>(&envelope, &other_wrapped_key, &org_key, &mut ctx);

        assert!(result.is_err());
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

        let Sealed {
            envelope,
            wrapped_key,
        } = seal_target_system(sample(), &org_key, &mut ctx).unwrap();

        let (envelope, wrapped_key) = (envelope.to_string(), wrapped_key.to_string());
        println!("const TEST_VECTOR_ORG_KEY: &str = \"{key_b64}\";");
        println!("const TEST_VECTOR_TARGET_SYSTEM_SEALED_DATA: &str = \"{envelope}\";");
        println!("const TEST_VECTOR_TARGET_SYSTEM_WRAPPED_KEY: &str = \"{wrapped_key}\";");
    }

    const TEST_VECTOR_ORG_KEY: &str =
        "MUgcMToL6hTXhQSr3bQuvJDw+P4y9vlRlvEQ36yFlgErQ0kdL5Xh3U92i/P3uJVk7X6ujV/uWO9usbo/X+0YcA==";
    const TEST_VECTOR_TARGET_SYSTEM_SEALED_DATA: &str = "g1hHpQEDA3gjYXBwbGljYXRpb24veC5iaXR3YXJkZW4uY2Jvci1wYWRkZWQEUHRhqF0LBJ8L12LJH4jFX186AAE4gQI6AAE4gAShBUxjXNBlDL/mPqel7U1Y8r2jmj4RoevZ2EkAV+RTDBLzvGAH6a0YBM8wm9G72AK+rpeVpLrQrFnAimeptb+OJj0Y5Wd2aC5ZZaRfeAzISQeSOGSk6M6Hfdn3YZR0RiJXbggAAc+rs0Zi7zSbfzffpmAfLxGuNG8tCEgInq8KijZnK1p8ff6uCEcNMhstzt5uFC3R1Mm/ua+iNiaYqXAZZLGn1vKQ8f4IC2G61SYtmgN70iZjea4HCad48Lrp16ny1/OAxAsR9iJgMTOHVDGXrAerGBKcJiho0My6CwVPQmQNHgNN1Ki/gvflT1FiYWFkiHat09pOfgGoDyjc3X8dbcgy";
    const TEST_VECTOR_TARGET_SYSTEM_WRAPPED_KEY: &str = "2.WakihY9ZIyZBuvrrvELJiQ==|j4sTuFZ7BqvcHiGKGcuI2tTjf3sZv29iUvh/I0eO/3EHzCuxsrEajOdZOneS9w1Hyag8agcO2IjmEOc0t3baBSpFqqZrmy/5UJ99n/zE3gU=|+DDgtyBastM+rPThuzq2ec4xa1ejGZMJaijzwf7aK9w=";

    #[test]
    fn target_system_test_vector() {
        let org_key =
            SymmetricCryptoKey::try_from(B64::try_from(TEST_VECTOR_ORG_KEY).unwrap()).unwrap();

        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();
        let org_key_id = ctx.add_local_symmetric_key(org_key);

        let envelope = DataEnvelope::from_str(TEST_VECTOR_TARGET_SYSTEM_SEALED_DATA).unwrap();
        let wrapped_key = EncString::from_str(TEST_VECTOR_TARGET_SYSTEM_WRAPPED_KEY).unwrap();
        let unsealed = unseal_target_system(&envelope, &wrapped_key, &org_key_id, &mut ctx).expect(
            "TargetSystemSealed wire format has changed in a backwards-incompatible way. \
                 Existing sealed data must remain deserializable.",
        );

        assert_eq!(unsealed, sample());
    }
}
