# bitwarden-access-token-crypto

Key material for access-token credentials: a 16-byte seed, the symmetric key derived from it for a
caller-defined [`KeyPurpose`], and wrapping/unwrapping an organization key under that derived key.
This crate knows nothing about a credential's wire format, client-kind segments, API key ids, client
secrets, or OAuth — see `bitwarden-access-token` for the credential built around this key material.

## Derivation

An [`AccessTokenSeed`] is 16 random bytes, generated when minting new key material. [`AccessTokenKey::derive`]
turns a seed and a [`KeyPurpose`] into a symmetric key via
`derive_shareable_key(seed, "accesstoken", Some(purpose))`.

A [`KeyPurpose`] is just a `&'static str` wrapped for type safety; this crate defines no purposes of
its own. Callers mint their own — typically one per kind of credential built on top of this crate —
and are responsible for:

- keeping every purpose string they define unique among the others they define, since two purposes
  that collide would derive the same key from the same seed, and
- never changing the string of a purpose once it has been used to mint issued credentials, since
  that would silently change which key those credentials derive.

The seed itself never needs to reach a server; it is the caller's job to transport it (e.g. embedded
in a token string) to whoever needs to re-derive the key.

## The two wrapped halves

Minting ([`make_access_token_key_material`]) produces an [`AccessTokenKeyMaterial`] with:

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
