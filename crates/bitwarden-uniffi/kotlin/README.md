# Android

Android builds needs vendored OpenSSL to function correctly. The easiest way to build this is by
using [cross](https://github.com/cross-rs/cross).

Note that the latest published version is very old, so we need to use a newer Git commit instead.

```bash
cargo install cross --locked --git https://github.com/cross-rs/cross.git --rev 185398b1b885820515a212de720a306b08e2c8c9
```

## Development

When building the Android SDK using Android Studio on MacOS you will need access to the local
`$PATH`, where cargo is installed. This can be done by starting Android Studio from the terminal.

```bash
open -a /Applications/Android\ Studio.app
```

## Building

Depending on which CPU architecture you will need to specify different targets. Please refer to the
[Android ABIs](https://developer.android.com/ndk/guides/abis) for more details.

```bash
mkdir -p ./sdk/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86_64,x86}

cross build -p bitwarden-uniffi --release --target=aarch64-linux-android
mv ../../../target/aarch64-linux-android/release/libbitwarden_uniffi.so ./sdk/src/main/jniLibs/arm64-v8a/libbitwarden_uniffi.so

cross build -p bitwarden-uniffi --release --target=armv7-linux-androideabi
mv ../../../target/armv7-linux-androideabi/release/libbitwarden_uniffi.so ./sdk/src/main/jniLibs/armeabi-v7a/libbitwarden_uniffi.so

cross build -p bitwarden-uniffi --release --target=x86_64-linux-android
mv ../../../target/x86_64-linux-android/release/libbitwarden_uniffi.so ./sdk/src/main/jniLibs/x86_64/libbitwarden_uniffi.so

cross build -p bitwarden-uniffi --release --target=i686-linux-android
mv ../../../target/i686-linux-android/release/libbitwarden_uniffi.so ./sdk/src/main/jniLibs/x86/libbitwarden_uniffi.so
```

### Schemas

```bash
./build-schemas.sh
```

### Publish

```bash
export GITHUB_ACTOR=username
export GITHUB_TOKEN=token

./gradlew sdk:publish
```
