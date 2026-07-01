# bitwarden-crypto-cipher-suite

Decides which cryptographic algorithms are allowed for the current user/environment.

Gov Mode (FedRAMP) deployments must use the FIPS-approved PBKDF2 for a new account's KDF, while
everyone else uses the modern Argon2id default.
