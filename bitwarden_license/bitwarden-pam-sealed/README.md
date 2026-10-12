# Bitwarden PAM Sealed Data

Commercial crate holding the PAM types that are sealed into opaque
[`DataEnvelope`](bitwarden_crypto::safe::DataEnvelope) blobs and stored by the server, plus the
shared password-strength floor applied to them.

A hostile PAM server (or a MitM on the access connector's TLS) controls every plaintext field it
hands the connector: which account is reset, how strong the new password is, which cipher stores it,
and whether sessions are killed. To close that gap, the admin client seals the security-relevant
fields of a target system ([`TargetSystemSealedV1`]) and a rotation config
([`RotationConfigSealedV1`]) into blobs whose content keys are wrapped by the organization key. The
server stores them opaquely; only holders of the organization key (the admin client and the access
connector) can read or verify them. See `docs/pam-rotation-sealed-config-plan.md` in `sdk-internal`
for the full threat model.

This crate depends only on `bitwarden-crypto`, so both the admin-side `bitwarden-pam` crate (which
uses `bitwarden_core::key_management::KeySlotIds`) and the access connector (which has its own,
independent `KeySlotIds` implementation) can share the same sealed types without the connector
pulling in the admin client.

## What's here

- [`TargetSystemSealedV1`] / [`RotationConfigSealedV1`]: the plaintext structs that get sealed.
- [`seal_target_system`] / [`unseal_target_system`] and [`seal_rotation_config`] /
  [`unseal_rotation_config`]: seal and unseal each type to/from an opaque string, generic over any
  `Ids: KeySlotIds`.
- [`SealedPasswordPolicy::validate`]: the shared password-strength floor (generator length range
  plus a minimum entropy bound), so both the admin client and the connector reject the same weak
  policies.
