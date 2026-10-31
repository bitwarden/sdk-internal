# bitwarden-encrypted-migrator

Runs the encrypted migrations of an account. An encrypted migration changes keys or encrypted data
to the current format, so it needs the keys of the unlocked account. A migration upgrades one of:

- the account on the server,
- the data of other accounts, for example the members of an organization that the user administers.

## Blocking and background migrations

This crate runs background migrations. Login, unlock, and sync do not wait for them. A migration
that must finish before the vault is usable blocks the unlock or the sync, and is not in this crate:

- after an unlock: `on_unlock_handler` in `bitwarden-core`,
- with the sync data: `handle_crypto_sync` in `bitwarden-crypto-sync-handler`.

Use a blocking migration only when the vault is not usable without it. A blocking migration that
calls a slow server keeps the user on the lock screen.

## When the migrations run

On WASM, the SDK schedules the migrations of each user:

- 5 seconds after an unlock or a sync, so that the sync data reaches state,
- 24 hours after each run, while the account stays unlocked.

Only one run of a user is in progress at a time. A failed migration runs again in the next run.

All SDK clients of a user share one schedule, because the TypeScript clients replace the SDK client
each time the keys of the account change in their state.
