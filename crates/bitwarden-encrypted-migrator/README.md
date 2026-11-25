# bitwarden-encrypted-migrator

Runs the encrypted migrations of an account. An encrypted migration changes keys or encrypted data
to the current format, so it needs the keys of the unlocked account. A migration upgrades one of:

- the local state of the user on this device, for example the PIN, biometric unlock, or the local
  user data key,
- the account on the server,
- the data of other accounts, for example the members of an organization that the user administers.

## Run the migrations

`EncryptedMigratorClient::run_migrations` runs each migration once, in registration order. A
migration logs its own errors, so a failed migration does not stop the others. This crate does not
decide when the migrations run.
