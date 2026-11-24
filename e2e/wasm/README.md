# WASM e2e tests

This is a set of end-to-end tests for the sdk. This aims to find issues that unit tests do not
uncover, and especially find issues where the FFI conversions are broken.

## Running them

From the repository root, build the wasm module and run the tests:

```sh
npm run e2e:wasm
```

To rerun the tests without rebuilding, from `e2e/wasm/`:

```sh
npm test
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
BW_LIVE_SERVER_URL=https://vault.example.com \
BW_LIVE_SEEDER_URL=https://seeder.example.com \
BW_LIVE_SEEDER_USERNAME=... \
BW_LIVE_SEEDER_PASSWORD=... \
npm run test:live
```

`BW_LIVE_SERVER_URL` is expanded to `<url>/api` and `<url>/identity`, which is how a self-hosted
install is laid out. A deployment that gives each service its own origin needs them named;
`GET <url>/api/config` reports what they are, under `environment`:

```sh
BW_LIVE_SERVER_URL=https://vault.usdev.bitwarden.pw \
BW_LIVE_API_URL=https://api.usdev.bitwarden.pw \
BW_LIVE_IDENTITY_URL=https://identity.usdev.bitwarden.pw \
BW_LIVE_SEEDER_URL=... BW_LIVE_SEEDER_USERNAME=... BW_LIVE_SEEDER_PASSWORD=... npm run test:live
```

Also optional: `BW_LIVE_DEVICE_IDENTIFIER`, which defaults to a fixed value so repeat runs look like
one returning device rather than a new one each time — a new device is what triggers new-device
verification — and `BW_LIVE_CLIENT_VERSION`, the version reported to the server, which a real server
requires and the emulator does not ask for.

### Test accounts

Each test seeds the accounts it needs, through the server's seeder API (`util/SeederApi`), with
`harness.accounts.create()`, and `harness.dispose()` destroys them when the test ends. Accounts are
seeded under one play id per harness, and destroyed by it, so a run leaves nothing behind; if a run
crashes before it can, the seeder's own cleanup removes plays older than a day. Live mode therefore
needs a server that runs the seeder with play-id tracking on, which no production server does.

The seeder stores each address with a random prefix (`1854b016+sdk-it-…@example.com`), and
`create()` answers the address the account logs in with. Test addresses use `example.com`, which
never delivers mail; `BW_LIVE_EMAIL_DOMAIN` changes it.

Seeded accounts are V1: the seeder doesn't make V2 accounts yet.

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
