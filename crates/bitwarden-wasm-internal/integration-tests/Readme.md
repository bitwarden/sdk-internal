# Integration Tests

This is a set of integration tests for the sdk. This aims to find issues that unit tests do not
uncover, and especially find issues where the FFI conversions are broken.

## Running them

To run the tests, the wasm module needs to be built, then the integration tests are run.

```sh
npm run build:test
```

## The server emulator

`server-emulator/` is a model of the backend. Accounts can be loaded into the emulator's database.
The emulator hooks the wasm sdk's fetch implementation to simulate the HTTP requests.

`client-emulator/` emulates platform services. Accounts can be loaded into the emulator's local
state.

## Running against a real server

Some tests can run against a live deployment instead of the emulator, to check that the requests the
SDK builds are ones a real server accepts — the one thing a model of the backend cannot tell you,
since it answers whatever it was written to answer. They are named `*.live.test.ts`, are skipped
unless configured, and never run in CI.

```sh
BW_LIVE_SERVER_URL=https://vault.example.com npm run test:live
```

`BW_LIVE_SERVER_URL` is expanded to `<url>/api` and `<url>/identity`, which is how a self-hosted
install is laid out. A deployment that gives each service its own origin needs them named;
`GET <url>/api/config` reports what they are, under `environment`:

```sh
BW_LIVE_SERVER_URL=https://vault.usdev.bitwarden.pw \
BW_LIVE_API_URL=https://api.usdev.bitwarden.pw \
BW_LIVE_IDENTITY_URL=https://identity.usdev.bitwarden.pw \
npm run test:live
```

### Test accounts

There are no long-lived test accounts. Each test creates the accounts it needs through registration,
as a client does, and `harness.dispose()` deletes them when it ends, pass or fail. Tests can run in
parallel without sharing an account, and a run leaves nothing behind. The same `harness.accounts`
works on the emulator, which is how a default run covers it.

Registration needs the email-verification token. A server with email verification off returns it.
One with it on mails it, and the tests read it back through the server's seeder API, named by
`BW_LIVE_SEEDER_URL`, `BW_LIVE_SEEDER_USERNAME` and `BW_LIVE_SEEDER_PASSWORD`.

Passwords are derived from the address and a secret: `BW_LIVE_SECRET`, or one generated once per
machine in `.live/` (gitignored). Every account created and deleted is recorded in
`.live/ledger.jsonl`, so before each live run, accounts a crashed run left behind for over an hour
are deleted.

Also optional:

- `BW_LIVE_EMAIL_DOMAIN`, the domain of test addresses, by default `example.com`, which never
  delivers mail.
- `BW_LIVE_DEVICE_IDENTIFIER`, which defaults to a fixed value so repeat runs look like one
  returning device rather than a new one each time.
- `BW_LIVE_CLIENT_VERSION`, the version reported to the server, which a real server requires and the
  emulator does not ask for.

A new account must be able to log in without two-factor, a captcha or new-device verification.

## Test vectors

`test-vectors/` records recorded test vectors. These can be loaded and tested against to ensure
compatibility with all cryptographic versions.

## Writing Tests

Tests should be written similar to how you would use the sdk in a real client. Do not mock
individual routes. Instead, ensure that the server emulator behaves reasonably closely to the real
server, then seed the data (if needed) and run your test.

A client only ever learns about an account from the wire: `ClientEmulator.sync` reads everything out
of the sync response, and its access token is the one the login returned. Do not reach into the
emulator's database for something a client would have been told — that is how the emulator drifts
away from the real server without any test noticing, and it is what stops a test from ever running
live.
