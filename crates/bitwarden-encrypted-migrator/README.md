# bitwarden-encrypted-migrator

Runs encrypted migrations. An encrypted migration changes keys or encrypted data to the current
format. State migrations run at startup, before any account is unlocked. An encrypted migration
needs the keys of an unlocked account, so it runs only while the account is unlocked. The password
manager client exposes `EncryptedMigratorClient` through `encrypted_migrator()`.

## Stages

Each migration has one stage. The stage controls whether login and unlock wait for the migration.

- **Foreground** migrations always run as part of login and unlock. They must finish before the
  vault is usable, so login and unlock wait for them.
- **Background** migrations run on a schedule while the account is unlocked. They never block the
  user. A sync, a timer, or an unlock can start them.

Only a migration that must finish before the vault is usable should block the unlock. Many
migrations can run while the user uses the vault, so the stage depends on the migration. For
example, a foreground migration that sends requests to a slow or unreachable server keeps the user
on the lock screen until the requests time out. Thus a migration uses the foreground stage only when
the vault is not usable before the migration finishes.

## When the background migrations run

The client calls `run_background_migrations`:

- after login,
- after unlock,
- after each sync while the account is unlocked,
- on a timer, for an account that stays unlocked for a long time, for example with the vault timeout
  set to never.
