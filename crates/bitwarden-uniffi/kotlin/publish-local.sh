#!/usr/bin/env bash
set -eo pipefail

cd "$(dirname "$0")"

SDK_REPO_ROOT="$(git rev-parse --show-toplevel)"

mkdir -p ./sdk/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86_64,x86}

# Build arm64 for emulator
cross build -p bitwarden-uniffi --release --target=aarch64-linux-android
mv $SDK_REPO_ROOT/target/aarch64-linux-android/release/libbitwarden_uniffi.so ./sdk/src/main/jniLibs/arm64-v8a/libbitwarden_uniffi.so

# Build other archs
if [ "$1" = "all" ]; then
    echo "Building for all architectures"
    
    cross build -p bitwarden-uniffi --release --target=armv7-linux-androideabi
    mv $SDK_REPO_ROOT/target/armv7-linux-androideabi/release/libbitwarden_uniffi.so ./sdk/src/main/jniLibs/armeabi-v7a/libbitwarden_uniffi.so

    cross build -p bitwarden-uniffi --release --target=x86_64-linux-android
    mv $SDK_REPO_ROOT/target/x86_64-linux-android/release/libbitwarden_uniffi.so ./sdk/src/main/jniLibs/x86_64/libbitwarden_uniffi.so

    cross build -p bitwarden-uniffi --release --target=i686-linux-android
    mv $SDK_REPO_ROOT/target/i686-linux-android/release/libbitwarden_uniffi.so ./sdk/src/main/jniLibs/x86/libbitwarden_uniffi.so
fi

# Generate latest bindings
./build-schemas.sh

# Publish to local maven (~/.m2/repository/com/bitwarden/sdk-android)
./gradlew sdk:publishToMavenLocal -Pversion=LOCAL
