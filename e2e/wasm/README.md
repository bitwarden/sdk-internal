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
since it answers whatever it was written to answer. They are named `*.live.test.ts` and pick their
backend from `BW_LIVE_SERVER_URL`: set, they run against that server; unset, a test that can also
run on the emulator does (`rotate-concurrency.live.test.ts`), and one that can't is skipped
(`rotate-user-keys.live.test.ts`). CI never sets it, so CI only ever runs them on the emulator.

```sh
BW_LIVE_SERVER_URL=https://vault.example.com \
BW_LIVE_EMAIL=someone@example.com \
BW_LIVE_PASSWORD=... \
npm run test:live
```

`BW_LIVE_SERVER_URL` is expanded to `<url>/api` and `<url>/identity`, which is how a self-hosted
install is laid out. A deployment that gives each service its own origin needs them named;
`GET <url>/api/config` reports what they are, under `environment`:

```sh
BW_LIVE_SERVER_URL=https://vault.usdev.bitwarden.pw \
BW_LIVE_API_URL=https://api.usdev.bitwarden.pw \
BW_LIVE_IDENTITY_URL=https://identity.usdev.bitwarden.pw \
BW_LIVE_EMAIL=... BW_LIVE_PASSWORD=... npm run test:live
```

Also optional: `BW_LIVE_DEVICE_IDENTIFIER`, which defaults to a fixed value so repeat runs look like
one returning device rather than a new one each time — a new device is what triggers new-device
verification — and `BW_LIVE_CLIENT_VERSION`, the version reported to the server, which a real server
requires and the emulator does not ask for.

The account needs to already exist, since the harness has no registration flow, and it needs
two-factor disabled, no captcha requirement, and no organization memberships. **These tests write to
the account**: they add a vault item if it has none, and they rotate its user key. Rotation is
re-runnable, but note that it upgrades a V1 account to V2 on the first run and that cannot be
undone.

### Seeding the live server from test vectors

A development server's SeederApi (`bitwarden/server` `util/SeederApi`) can load the same test
vectors the emulator does, through its `TestVectorUserScene`. Point the harness at it, and every
test seeds a fresh account from its own vector instead of sharing one, so `BW_LIVE_EMAIL` and
`BW_LIVE_PASSWORD` aren't needed:

```sh
BW_LIVE_SERVER_URL=http://localhost:4000 \
BW_LIVE_API_URL=http://localhost:4000 \
BW_LIVE_IDENTITY_URL=http://localhost:33656 \
BW_LIVE_SEEDER_URL=http://localhost:5047 \
BW_LIVE_SEEDER_USERNAME=... BW_LIVE_SEEDER_PASSWORD=... \
npm run test:live
```

Only what a server holds is sent: wrapped keys, public keys, the authentication hash and the
encrypted vault. Each test's account is deleted again when the test ends (`DELETE /seed/{playId}`).
The scene seeds master-password vectors only.

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
