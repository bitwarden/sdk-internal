# bitwarden-access-token

Minting, wire format, and opening of access-token credentials: one-time tokens that let an
unattended client authenticate and recover an organization key, without a human ever handling the
key directly. Supports two [`AccessTokenKind`]s: the PAM access connector, and Secrets Manager. The
Secrets Manager kind's key derivation matches the web vault's and `bitwarden-core`'s existing access
tokens, so a token minted by either derives the same key here.

Key derivation and the key material itself (the seed, and wrapping/unwrapping the organization key)
live in `bitwarden-access-token-crypto`, which this crate depends on; this crate owns only the wire
format and OAuth credential built around that key material.

## Format

A token is one of two shapes, depending on whether its [`AccessTokenKind`] has a wire segment:

```text
0.<client-kind>.<api-key-id>.<client-secret>:<b64-16-byte-seed>
0.<api-key-id>.<client-secret>:<b64-16-byte-seed>
```

- `0` is the only version this crate accepts.
- `<client-kind>` (the four-segment shape) names which [`AccessTokenKind`] the token is for (e.g.
  `access-connector`). It must match the server's provider prefix for that client kind, or the token
  parses but cannot authenticate. [`AccessTokenKind::SecretsManager`] has no such segment, so it
  uses the three-segment shape instead.
- `<api-key-id>` and `<client-secret>` are the OAuth client-credentials pair the holder presents to
  the identity server. The OAuth `client_id` is `<client-kind>.<api-key-id>` for a kind with a
  segment, or the bare `<api-key-id>` otherwise.
- The seed after the `:` never reaches the server. Both sides derive an
  `bitwarden_access_token_crypto::AccessTokenKey` from it using
  [`AccessTokenKind::key_purpose`], so the two kinds never share a key even from the same seed.
  Secrets Manager's purpose is `"sm-access-token"`, which every issued Secrets Manager token depends
  on, so it can never change.

## Minting and opening

Minting ([`make_access_token_secrets`]) wraps `bitwarden-access-token-crypto`'s key material and
also knows how to assemble the wire string ([`AccessTokenSecrets::into_token`]). Opening
([`AccessToken::open_payload`]) parses the token, re-derives the key, and forwards to the crypto
crate to recover the organization key — see that crate's README for what the `encrypted_payload` and
`key` fields actually hold and how derivation works.
