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

## Test vectors

`test-vectors/` records recorded test vectors. These can be loaded and tested against to ensure
compatibility with al cryptographic versions.

## Writing Tests

Tests should be written similar to how you would use the sdk in a real client. Do not mock
individual routes. Instead, ensure that the server emulator behaves reasonably closely to the real
server, then seed the data (if needed) and run your test.
