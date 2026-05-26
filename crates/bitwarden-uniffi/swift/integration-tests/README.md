# BitwardenSdk Swift integration tests

XCTest integration tests for the Swift UniFFI bindings, mirroring the
`crates/bitwarden-wasm-internal/integration-tests/` suite.

## Running

Build the parent xcframework first:

```sh
(cd ../ && ./build.sh)
```

Then run the tests against an iOS Simulator (from this `integration-tests/`
directory):

```sh
DEVICE_ID=$(xcrun simctl list devices available | awk -F '[()]' '/iPhone/{print $2; exit}')
xcodebuild test \
  -scheme IntegrationTests-Package \
  -destination "id=$DEVICE_ID"
```

The first command picks the UDID of the first available iPhone simulator so the
test command works regardless of which Xcode/iOS version is installed. The
scheme is named `IntegrationTests-Package` because Swift Package Manager
appends `-Package` to the package name when generating xcodebuild schemes.
