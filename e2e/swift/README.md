# BitwardenSdk Swift e2e tests

XCTest e2e tests for the Swift UniFFI bindings, mirroring the [`e2e/wasm/`](../wasm/) suite.

## Running

From the repository root, build the xcframework and run the tests on an iOS Simulator:

```sh
npm run e2e:swift
```

To rerun the tests without rebuilding:

```sh
./e2e/swift/test.sh
```
