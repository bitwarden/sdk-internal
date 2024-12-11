
{
  description = "sdk-internal flake for local development and CI";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };
  outputs = {
    self,
    nixpkgs,
    ...
  }: let
    supportedSystems = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    forAllSystemTypes = fn: nixpkgs.lib.genAttrs supportedSystems fn;
  in {
    devShells = forAllSystemTypes (system: let
      pkgs = import nixpkgs {inherit system;};
    in {
      default = let
        rustToolChainVersion = "stable";
      in
      pkgs.mkShell {
        buildInputs = [
          pkgs.rustup           # Rust toolchain manager
          pkgs.cargo            # Rust package manager and build system
          pkgs.cargo-llvm-cov   # Test coverage generator for cargo
          pkgs.cargo-release    # Extension for cargo for release builds
          pkgs.androidsdk       # Android SDK for building Android apps
          pkgs.androidndk       # Android NDK for building native code for Android
          pkgs.gradle           # Build automation tool for Java projects
          pkgs.nodejs           # Node.js for JavaScript runtime
          pkgs.binaryen         # Binaryen for WebAssembly tools
          pkgs.wasm-bindgen-cli # wasm-bindgen CLI for building WASM
        ];
        # `packages` contains tooling not directly related to building and
        # testing the software. In this case it is a home for custom scripts
        # that abstract wordy shell commands for ease of memory and reuse.
        # It might be smart to move some of these to a justfile to allow
        # folks not running the devshell to use them as well.
        packages = [
          (pkgs.writeScriptBin "run-build" ''
            cargo build
          '')
          (pkgs.writeScriptBin "setup-toolchain" ''
            rustup default ${rustToolChainVersion}
          '')
          (pkgs.writeScriptBin "generate-test-coverage" ''
            cargo llvm-cov \
              --all-features \
              --lcov \
              --output-path lcov.info \
              --ignore-filename-regex "crates/bitwarden-api-"
          '')
          (pkgs.writeScriptBin "run-tests" ''
            cargo test
          '')
          (pkgs.writeScriptBin "ci-build" ''
            if [ -z "$1" ]; then
              echo "No package specified"
              exit 1
            fi
            if [ -z "$2" ]; then
              echo "No build target specified"
              exit 1
            fi
            package=$1
            build_target=$2
            cargo build \
              --release \
              --package $package \
              --target $build_target
          '')
          (pkgs.writeScriptBin "ci-tests" ''
            cargo test
          '')
          (pkgs.writeScriptBin "ci-dry-run" ''
            cargo-release release publish \
              --no-publish \
              -p bitwarden-api-api \
              -p bitwarden-api-identity \
              -p bitwarden
          '')
          (pkgs.writeScriptBin "build-android" ''
            if [ -z "$1" ]; then
              echo "No target specified"
              exit 1
            fi
            target=$1
            cross build -p bitwarden-uniffi --release --target=$target
          '')
          (pkgs.writeScriptBin "move-artifacts" ''
            mkdir -p crates/bitwarden-uniffi/kotlin/sdk/src/main/jniLibs/armeabi-v7a
            mkdir -p crates/bitwarden-uniffi/kotlin/sdk/src/main/jniLibs/arm64-v8a
            mkdir -p crates/bitwarden-uniffi/kotlin/sdk/src/main/jniLibs/x86
            mkdir -p crates/bitwarden-uniffi/kotlin/sdk/src/main/jniLibs/x86_64
            mv ./target/armv7-linux-androideabi/release/libbitwarden_uniffi.so crates/bitwarden-uniffi/kotlin/sdk/src/main/jniLibs/armeabi-v7a/libbitwarden_uniffi.so
            mv ./target/aarch64-linux-android/release/libbitwarden_uniffi.so crates/bitwarden-uniffi/kotlin/sdk/src/main/jniLibs/arm64-v8a/libbitwarden_uniffi.so
            mv ./target/i686-linux-android/release/libbitwarden_uniffi.so crates/bitwarden-uniffi/kotlin/sdk/src/main/jniLibs/x86/libbitwarden_uniffi.so
            mv ./target/x86_64-linux-android/release/libbitwarden_uniffi.so crates/bitwarden-uniffi/kotlin/sdk/src/main/jniLibs/x86_64/libbitwarden_uniffi.so
          '')
          (pkgs.writeScriptBin "generate-bindings" ''
            ./build-schemas.sh
          '')
          (pkgs.writeScriptBin "publish" ''
            ./gradlew sdk:publish
          '')
          (pkgs.writeScriptBin "build-wasm" ''
            ./build.sh -r
          '')
        ];
        shellHook = ''
          setup-toolchain
          echo -e "\033[1;34m✔ Development shell initilized\033[0m"
        '';
        env = {
          RUSTFLAGS="-D warnings"; # Fail on warnings
          CARGO_TERM_COLOR = "always"; # Preserve colored output in CI
        };
      };
    });
  };
}
