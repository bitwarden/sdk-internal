# Bitwarden Locking

Contains the high-level locking API used to unlock and lock a client, including session-key
generation and unlocking by session key.

Underlying `initialize_user_crypto_*` primitives remain in `bitwarden-core`; this crate consumes
them to keep the dependency direction one-way.
