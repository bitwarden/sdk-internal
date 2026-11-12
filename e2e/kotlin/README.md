# BitwardenSdk Kotlin e2e tests

JUnit e2e tests for the Kotlin UniFFI bindings, mirroring the [`e2e/swift/`](../swift/) suite. They
call the SDK through generated bindings and the real native library, so they check what Rust tests
cannot: that the generated Kotlin code and the Rust side agree on how every argument and result
crosses the FFI boundary.

The tests run on the host JVM, without an emulator or the Android SDK, the way UniFFI tests its own
Kotlin bindings. This is a standalone Gradle build with its own `settings.gradle`, so it does not
configure the Android project in `crates/bitwarden-uniffi/kotlin`.

## Running

Requires a JDK (17 or later) and a Rust toolchain. From the repository root:

```sh
npm run e2e:kotlin
```

This runs two scripts:

1. `crates/bitwarden-uniffi/kotlin/build-jvm.sh` builds `bitwarden-uniffi` for the host
   (`target/debug`; set `DEBUG_MODE=false` for a release build) and generates the Kotlin bindings.
   It writes the bindings and a copy of the native library to `crates/bitwarden-uniffi/kotlin/jvm`.
2. `e2e/kotlin/test.sh` runs the tests with the Gradle wrapper in `crates/bitwarden-uniffi/kotlin`,
   pointing JNA at that library.

To rerun the tests without rebuilding:

```sh
./e2e/kotlin/test.sh
```

Arguments are passed to Gradle, for example `./e2e/kotlin/test.sh --tests '*PinLockTests*'`. The
SDK's logs are off unless `RUST_LOG` is set, for example `RUST_LOG=debug ./e2e/kotlin/test.sh`.

## How the bindings differ from the Android ones

The bindings are generated with `android = false` for every crate, where the Android package sets
`android = true` in each crate's `uniffi.toml`. `build-jvm.sh` writes the override to
`jvm/uniffi-jvm.toml` and passes it with `--config`.

In UniFFI 0.32 that setting only selects the cleaner that frees Rust objects when their Kotlin
wrapper is garbage collected: `android.system.SystemCleaner` on Android, `java.lang.ref.Cleaner` on
the JVM. The Android one does not exist on a desktop JVM. The code that lowers arguments and lifts
results, including how records, enums and errors are serialized, is the same in both.
