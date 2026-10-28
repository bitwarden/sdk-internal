# Bitwarden Organization Crypto Crate

The `bitwarden-organization-crypto` crate surfaces APIs for safely manipulating
organization-specific cryptography. Similar to the `bitwarden-crypto` crate, this is meant to be a
basic dependency used by organization-related feature crates.

**This is not a client crate** and _shall not_ depend on `bitwarden-core` as a result.

## Organization keys

- `OrganizationPrivateKey`: the private key of the organization. The organization key unwraps it
  into the key store context.
- `OrganizationSharedKey`: the organization key, shared with one member. The API calls it the `key`
  of the membership.
- `AccountRecovery`: the user key of a member, held by the organization for account recovery. The
  API calls it the "reset password key".

`OrganizationSharedKey` and `AccountRecovery` are versioned enums. Each version matches an Org
Membership version. V1 encapsulates a key to a public key without sender authentication. V2
(planned) seals keys between identities, with sender authentication.

`make` shares a key only after the public key of the recipient passes a `TrustProof`:

- `TrustProof::ManuallyTrusted`: the thumbprint of a public key that a person verified, or that came
  over a channel that the server does not control, for example an invite link.
- `TrustProof::CryptographicallyTrusted`: a cryptographic proof that the public key belongs to the
  recipient. The only proof now is the matching private key in the key store context, for example
  the own key pair of the user, or the organization key pair that an admin unwraps.

Some V1 flows cannot verify the public key. These flows use `make_untrusted`, which V2 does not
have.

A V1 to V2 upgrade of a member's user key leaves the account recovery of the V1 user key in place.
An admin replaces it with `AccountRecovery::make_after_v2_upgrade`, which accepts only a V2 user key
with the key id that the server reported.
