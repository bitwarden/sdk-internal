---
paths:
  - "crates/**"
  - "bitwarden_license/**"
---

# Using key-management-owned keys

Keys owned by `@bitwarden/team-key-management-dev`:

- User Key
- Master Key
- User Private Key
- User Signature Key
- Organization Key
- Organization Private Key

must undergo review and requires approval for new usages.

- **New wrapping or new access path** — wrapping the key with a new key or in a new format, or
  otherwise exposing a new means of obtaining it.
- **Key derivation** — deriving any new key from it.
- **Anything that blocks rotation** — using the key such that rotating it would break data or
  access.

Encrypting and decrypting with them generally does not require approval.

## Rotation-blocking, concretely

A key can be rotated only if every wrapped copy can be re-wrapped at rotation time. So if the key is
wrapped in a way that is reachable only locally — a single device, a single user, hardware-bound
material — while other devices or users also need the key, rotation is blocked.

Example: wrapping the user key with a local PIN key can prevent rotation, and requires a
construction such as the V2UpgradeToken to resolve.

There are ways to fix this such as with the InviteLink or RotateableKeySet.

## Dangerous Get Key

`dangerous_get_symmetric_key` and other functions that get raw keys outside of crypto modules owned
by `@bitwarden/team-key-management-dev` need to be reviewed by `@bitwarden/team-key-management-dev`.
