use bitwarden_crypto::{
    EncString, KeySlotIds, KeyStoreContext, generate_versioned_sealable,
    safe::{
        DataEnvelope, DataEnvelopeError, DataEnvelopeNamespace, SealableData, SealableVersionedData,
    },
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::Sealed;

/// Security-relevant fields of a PAM rotation config. Sealed by the admin client so a hostile
/// server can't choose the account, cipher, or session-termination behavior.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RotationConfigSealedV1 {
    /// Cross-checked against the claim and the other blob to stop swaps.
    pub target_system_id: Uuid,
    /// Checked against the claim's `cipher_id`.
    pub cipher_id: Uuid,
    /// The account to rotate. Never interpolate unsanitized into a shell command or query.
    pub account_identity: String,
    /// ANDed with the target's `supports_session_termination`.
    pub terminate_sessions: bool,
}
impl SealableData for RotationConfigSealedV1 {}

generate_versioned_sealable!(
    RotationConfigSealed,
    DataEnvelopeNamespace::PamRotationConfig,
    [
        RotationConfigSealedV1 => "1",
    ]
);

/// Seals `data` under `org_key`.
pub fn seal_rotation_config<Ids: KeySlotIds>(
    data: RotationConfigSealedV1,
    org_key: &Ids::Symmetric,
    ctx: &mut KeyStoreContext<Ids>,
) -> Result<Sealed, DataEnvelopeError> {
    let versioned: RotationConfigSealed = data.into();
    let (envelope, wrapped_key) = DataEnvelope::seal_with_wrapping_key(versioned, org_key, ctx)?;
    Ok(Sealed {
        envelope,
        wrapped_key,
    })
}

/// Unseals a [`RotationConfigSealedV1`] from the output of [`seal_rotation_config`].
pub fn unseal_rotation_config<Ids: KeySlotIds>(
    envelope: &DataEnvelope,
    wrapped_key: &EncString,
    org_key: &Ids::Symmetric,
    ctx: &mut KeyStoreContext<Ids>,
) -> Result<RotationConfigSealedV1, DataEnvelopeError> {
    let versioned: RotationConfigSealed =
        envelope.unseal_with_wrapping_key(org_key, wrapped_key, ctx)?;
    let RotationConfigSealed::RotationConfigSealedV1(data) = versioned;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitwarden_crypto::{KeyStore, SymmetricCryptoKey};
    use bitwarden_encoding::B64;

    use super::*;
    use crate::test_support::TestIds;

    fn sample() -> RotationConfigSealedV1 {
        RotationConfigSealedV1 {
            target_system_id: Uuid::parse_str("8c6e7d1a-3e3f-4a5b-9c1d-2f3e4d5c6b7a").unwrap(),
            cipher_id: Uuid::parse_str("1a2b3c4d-5e6f-4789-9abc-def012345678").unwrap(),
            account_identity: "svc-rotation@example.com".to_string(),
            terminate_sessions: true,
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
        } = seal_rotation_config(data.clone(), &org_key, &mut ctx).unwrap();
        let unsealed = unseal_rotation_config(&envelope, &wrapped_key, &org_key, &mut ctx).unwrap();

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
        } = seal_rotation_config(data.clone(), &org_key, &mut ctx).unwrap();
        let envelope: DataEnvelope = envelope.to_string().parse().unwrap();
        let wrapped_key: EncString = wrapped_key.to_string().parse().unwrap();

        let unsealed = unseal_rotation_config(&envelope, &wrapped_key, &org_key, &mut ctx).unwrap();
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
        } = seal_rotation_config(sample(), &org_key, &mut ctx).unwrap();
        let result =
            unseal_rotation_config::<TestIds>(&envelope, &wrapped_key, &wrong_key, &mut ctx);

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
        } = seal_rotation_config(sample(), &org_key, &mut ctx).unwrap();

        let (envelope, wrapped_key) = (envelope.to_string(), wrapped_key.to_string());
        println!("const TEST_VECTOR_ORG_KEY: &str = \"{key_b64}\";");
        println!("const TEST_VECTOR_ROTATION_CONFIG_SEALED_DATA: &str = \"{envelope}\";");
        println!("const TEST_VECTOR_ROTATION_CONFIG_WRAPPED_KEY: &str = \"{wrapped_key}\";");
    }

    const TEST_VECTOR_ORG_KEY: &str =
        "vA1+lDkWyNN0ZVTRLJMs64LXMbwW+h0x1nN2nPJ5clYtuXLL3ek3bKW/uDb1Kmye7vz7o7hADuZBDeMuQfoCiw==";
    const TEST_VECTOR_ROTATION_CONFIG_SEALED_DATA: &str = "g1hHpQEDA3gjYXBwbGljYXRpb24veC5iaXR3YXJkZW4uY2Jvci1wYWRkZWQEUOwuU91Xcz4pzHy3rmrPeP06AAE4gQI6AAE4gAWhBUyORP6msVGzzmXPo29YoSD80pwt83q+nnI+6B519Ur9T+t0PHxX50GRwzeJTE5zmD/fG5D5a32OrKkbeePwL/BDUjL4YPu44XC9Fp3T2vEUunJp4G4pm8gHWZdAmp6Pz2zNsq3nRSBBKUfkpQVRPf0+oCUVIRJF8UYIY+QkZmHimmNZi/DrwiXbNusjO7DjM5s2X5cnhxhLwpBaBwnyqMnCNLuptbBZYYKluNkebXFK";
    const TEST_VECTOR_ROTATION_CONFIG_WRAPPED_KEY: &str = "2.n0nzXEnaK2oxw+szuM3OZA==|DoiILS1QEEt7VbD5VyBmVuhhlkdoqkXNeAhxvNHCJQbq5/9Ut89nUZ45uMNfqf0kaM0ttRAHly30433dJ8PwplyKnZqU5OoaoxBxWY7C1SA=|ZP7wSGPyte0dkkjjxQxZiJ/gBaK8iy/1MEuw+O9UZGM=";

    #[test]
    fn rotation_config_test_vector() {
        let org_key =
            SymmetricCryptoKey::try_from(B64::try_from(TEST_VECTOR_ORG_KEY).unwrap()).unwrap();

        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();
        let org_key_id = ctx.add_local_symmetric_key(org_key);

        let envelope = DataEnvelope::from_str(TEST_VECTOR_ROTATION_CONFIG_SEALED_DATA).unwrap();
        let wrapped_key = EncString::from_str(TEST_VECTOR_ROTATION_CONFIG_WRAPPED_KEY).unwrap();
        let unsealed = unseal_rotation_config(&envelope, &wrapped_key, &org_key_id, &mut ctx)
            .expect(
                "RotationConfigSealed wire format has changed in a backwards-incompatible \
                     way. Existing sealed data must remain deserializable.",
            );

        assert_eq!(unsealed, sample());
    }
}
