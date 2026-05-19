# Bitwarden Unlock

Contains the high-level `unlock` API used to unlock/lock a client, including session-key generation
and unlocking by session key.

Underlying `initialize_user_crypto_*` primitives remain in `bitwarden-core`; this crate consumes
them to keep the dependency direction one-way.
