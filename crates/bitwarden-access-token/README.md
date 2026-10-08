# bitwarden-access-token

Minting, wire format, and opening of access-token credentials: one-time tokens that let an
unattended client authenticate and recover an organization key, without a human ever handling the
key directly. Supports two [`AccessTokenKind`]s: the PAM access connector, and Secrets Manager. The
Secrets Manager kind's key derivation matches the web vault's and `bitwarden-core`'s existing access
tokens, so a token minted by either derives the same key here.

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
- The seed after the `:` never reaches the server. Both sides run it through
  `derive_shareable_key(seed, "accesstoken", Some(kind.derive_info()))` to reach the same symmetric
  key without it crossing the wire. `derive_info` is per [`AccessTokenKind`], so the two kinds never
  share a key even from the same seed. Secrets Manager's info is `"sm-access-token"`, which every
  issued Secrets Manager token depends on, so it can never change.

## The three halves

Minting (`make_access_token_secrets`) produces:

- `encrypted_payload`: `{"encryptionKey": <b64 organization key>}` encrypted under the derived key.
  Sent to the issuing server, later returned to the token holder on authentication, and opened with
  [`AccessToken::open_payload`].
- `key`: the derived key's base64, encrypted under the organization key. Lets the organization
  recover the derived key later without needing the token.
- the seed, which only [`AccessTokenSecrets::into_token`] ever turns into the wire string.

Opening ([`AccessToken::open_payload`]) reverses the first half: given the token (holding the
re-derived key) and the `encrypted_payload` string the server returned, it recovers the organization
key and installs it at the caller-supplied slot in a [`bitwarden_crypto::KeyStoreContext`] — the raw
key material never leaves this crate.
