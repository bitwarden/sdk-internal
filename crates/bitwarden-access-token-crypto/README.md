# bitwarden-access-token-crypto

Key material for access-token credentials: a 16-byte seed, the symmetric key derived from it for a
[`KeyPurpose`], and wrapping/unwrapping an organization key under that derived key. This crate knows
nothing about a credential's wire format, client-kind segments, API key ids, client secrets, or
OAuth — see `bitwarden-access-token` for the credential built around this key material.

## Derivation

An [`AccessTokenSeed`] is 16 random bytes, made along with new key material.
[`AccessTokenKey::derive`] turns a seed and a [`KeyPurpose`] into a symmetric key via
`derive_shareable_key(seed, "accesstoken", Some(purpose))`.

A [`KeyPurpose`] is a closed enum of the purposes this crate defines, typically one per kind of
credential built on top of it. Each maps to an HKDF `info` string, and adding a purpose is a
reviewed change to this crate. The crate's own enum is responsible for:

- keeping every purpose string unique among the others, since two purposes that collide would derive
  the same key from the same seed, and
- never changing the string of a purpose once it has been used to mint issued credentials, since
  that would silently change which key those credentials derive.

The seed itself never needs to reach a server; it is the caller's job to transport it (e.g. embedded
in a token string) to whoever needs to re-derive the key.

## The two wrapped halves

Minting ([`AccessTokenKeyMaterial::make`]) produces an [`AccessTokenKeyMaterial`] with:

- `encrypted_payload`: `{"encryptionKey": <b64 organization key>}` encrypted under the derived key.
  Handed to the credential holder, who can later recover the organization key via
  [`AccessTokenKey::open_payload`].
- `key`: the derived key's base64, encrypted under the organization key. Lets the organization
  recover the derived key later without needing the credential itself.
- the seed, reachable only by consuming the material with [`AccessTokenKeyMaterial::into_seed`],
  since it is the one value the caller must thread through to its own wire format.

Opening ([`AccessTokenKey::open_payload`]) reverses the first half: given a key re-derived from the
seed and the `encrypted_payload` string, it recovers the organization key and installs it at the
caller-supplied slot in a [`bitwarden_crypto::KeyStoreContext`] — the raw key material never leaves
this crate.

See `examples/access_token.rs` for the full flow.
