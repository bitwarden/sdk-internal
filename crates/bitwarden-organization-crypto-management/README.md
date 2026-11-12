# Bitwarden Organization Crypto Management

Contains operations that manage the cryptographic state of the user's organizations. These
operations use the organization keys of the account in the key store, and talk to the server.

Organization cryptographic primitives are in `bitwarden-organization-crypto`, which is not a client
crate.

## Organization key id backfill

Records the id of each organization key with the server, for organizations where the server has no
id. Only Owners and Admins can record the id.
