/*
  Welcome to the sdk-internal nix flake!

  = Here's what it can do: =

  1. Provide fully reproducible builds with locked versions of key build
     technologies like rust, android dependencies, etc. Only Xcode is an
     exception to this.
  2. Enable the ability to run all of CIs builds locally in sandboxed
     environments without installing any software permanently on the building
     machine. Build dependencies are garbage collected after use.
  3. Automatically setup and maintain complicated, version locked local
     development environments painlessly.

  = You can use this flake by =

  1. Installing nix on your mac or linux machine (or wsl for windows)
  2. Ensuring flakes, nix-command, impure-derivations, and ca-derivations are
     enabled as experimental features in your nix configuration
  3. Opening a shell in this directory
  4. Running a nix command

  = You can setup nix by =

  1. Installing Nix:
     https://nixos.org/download/
  2. Enabling required experimental features by creating or editing /etc/nix/nix.conf:
     ```
     echo "experimental-features = nix-command flakes impure-derivations ca-derivations" | sudo tee -a /etc/nix/nix.conf
     ```
     > [!] Our flake depends on these experimental features for using nix flakes, and for building the iOS library.
  3. Restarting the nix daemon:
     ```
     # on Linux
     sudo systemctl restart nix-daemon
     ```
     ```
     # on Mac
     sudo launchctl kickstart -k system/org.nixos.nix-daemon
     ```
  4. Start a new shell

  = Some example commands for using this flake =

  == For starting development environments ==

  ```
  # This builds a default development environment ready for rust
  # development. Run it, then you can run `bacon` to watch, build and test
  # the project!
  nix develop
  ```
  ```
  # This runs a few checks:
  # - a simple build
  # - rust tests
  # - rust lints
  # - rust formatting
  # - js formatting,
  # - a check for unused dependencies
  # - a rust workspace sorter
  # - a cloc run
  # - a memory testing test suite (linux only)
  #
  # These are the same checks run in CI!
  # `nix build` is an alias for `nix build .#checks`
  nix build
  ```

  == For building artifacts ==

  ```
  # This builds a single rust crate (see Cargo.toml for the list of possible crates) for release
  nix build .#bitwarden-api-api
  ```
  ```
  # This builds all the rust crates for release
  nix build .#all-rust-crates
  ```
  ```
  # This builds the rust documentation for the package
  nix build .#rustdoc
  ```
  ```
  # This builds the android library for release
  nix build .#android
  ```
  ```
  # This builds the iOS library for release
  nix build .#swift
  ```
  ```
  # This builds the wasm library for release
  nix build .#wasm
  ```
  ```
  # This builds all packaged bianries: rust crates, wasm, swift, and android
  nix build .#builds
  ```
  ```
  # This runs all checks and all builds.
  nix build .#everything
  ```

  > [!] You can inspect the output of any build command by browsing the `result` folder that is produced!
  > `nix build .#checks-and-builds` will output:
  > - a `logs` folder with logs from every check
  > - a `libs` folder with subfolders for each build type
  > - artifacts and libraries generated for each build type

  = Furthur Reading =

  Nix's documentation can be a bit scattered. Here are some reference materials that are good:

  - <https://nix.dev>
  - <https://zero-to-nix.com>
  - <https://nixos.org/guides/nix-pills/>
*/
{
  description = ''
    The internal Bitwarden SDK
  '';

  inputs = {
    # Which version of nixpkgs to use. 24.11 is the latest stable release.
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";

    # rust-overlay provides `rust-bin` which offers:
    # - Easy access to multiple Rust versions/channels (stable, beta, nightly)
    # - Simple target platform configuration (doing this straight from nixpkgs has a lot of boilerplate)
    # - Pre-built binaries (faster than building from source)
    #
    #  This is helpful in the SDK because it makes cross-compilation easier
    rust-overlay = {
      url = "github:oxalica/rust-overlay";

      # We override the nixpkgs version used by inputs for consistency
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # android-nixpkgs provides all packages from the Android SDK repository as nix packages
    #
    # This is helpful for fetching Android NDK dependencies to build the android bindings
    android-nixpkgs = {
      url = "github:tadfisher/android-nixpkgs/stable";

      # We override the nixpkgs version used by inputs for consistency
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
  outputs =
    # We pass in all our inputs as function arguements to generate outputs
    {
      self,
      nixpkgs,
      rust-overlay,
      android-nixpkgs,
      ...
    }:
    let
      # These are all the systems nix runs on
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      # This function essentially acts as a for loop over each supported system
      allSupportedSystems = fn: nixpkgs.lib.genAttrs supportedSystems fn;

      # This function provides rust
      mkRustBuildInputs =
        pkgs: target: with pkgs; [
          # Rust stable is used for most tasks
          (rust-bin.stable.latest.default.override {
            extensions = [ "rust-src" ];
            targets = [ target ];
          })
          # Rust nightly is used sometimes, like for formatting
          (rust-bin.nightly.latest.default.override {
            extensions = [
              "rust-src"
              "rustfmt"
            ];
            targets = [ target ];
          })
          # nextest is the prefered test runner because it is fast
          cargo-nextest

          # used to sort workspaces
          cargo-sort

          # used to detect unused dependencies
          cargo-udeps

          # used to format javascript files
          nodejs_22
          nodePackages.npm
          nodePackages.prettier
        ];

      rustEnvVariables = {
        # TODO: This is off right now because we do fail on some warnings.
        # Fail on warnings
        # RUSTFLAGS = "-D warnings";

        # Preserve colors in CI
        CARGO_TERM_COLOR = "always";
      };

      # This function provides the android dependencies that android-nixpkgs
      # outputs
      mkAndroidSdk =
        system:
        android-nixpkgs.sdk.${system} (
          sdkPkgs: with sdkPkgs; [
            build-tools-34-0-0
            cmdline-tools-latest
            platform-tools
            platforms-android-34
            ndk-27-0-11902837
            ndk-bundle
          ]
        );

      # This function provides all dependencies needed to build for android
      # This includes the android SDK software above, as well as jdk and rust.
      mkAndroidBuildInputs =
        system: pkgs: target:
        with pkgs;
        [
          (mkAndroidSdk system)
          jdk17_headless
        ]
        ++ (mkRustBuildInputs pkgs target);

      # Gradle is used to turn the android artifacts into a library, and it
      # requires git.
      mkAndroidLibraryBuildInputs =
        system: pkgs: target:
        with pkgs;
        [
          git # needed for gradle
        ]
        ++ (mkAndroidBuildInputs system pkgs target);

      # This function provides all of gradle's declared dependencies from the
      # manually generated gradle.lock file and prepares them for use by gradle.
      mkMavenRepo =
        pkgs:
        let
          # This gradle lock file was generated manually using nix2gradle.
          # Gradle doesn't have a lockfile on its own.
          gradleLock = builtins.fromJSON (builtins.readFile ./gradle.lock);

          # Convert the lock file into a list of artifacts to fetch
          mavenArtifacts = pkgs.lib.concatLists (
            pkgs.lib.mapAttrsToList (
              dep: files:
              pkgs.lib.mapAttrsToList (filename: meta: {
                path = "${builtins.replaceStrings [ ":" ] [ "/" ] dep}/${filename}";
                inherit (meta) url hash;
              }) files
            ) gradleLock
          );
        in
        pkgs.stdenv.mkDerivation {
          name = "maven-repo";
          # Fetch all the maven dependencies from the web
          buildCommand = ''
            mkdir -p $out
            ${pkgs.lib.concatMapStrings (artifact: ''
              mkdir -p $(dirname $out/${artifact.path})
              cp ${
                pkgs.fetchurl {
                  url = artifact.url;
                  sha256 = artifact.hash;
                }
              } $out/${artifact.path}
            '') mavenArtifacts}
          '';
        };
    in
    {
      # Each package in "packages" represents the output of a `nix build` command
      # Using "allSupportedsystems" here means we create these packages for
      # each nix-supported system (i.e mac and linux on x86 or arm)
      packages = allSupportedSystems (
        system:
        let
          # nixpkgs is where all the software used by builds (besides Xcode)
          # comes from
          pkgs = import nixpkgs {
            # "system" being the machine running the build (i.e aarch64_darwin)
            inherit system;

            # We have to extend nixpkgs to know about the rust-overlay so we
            # can use its provided rust
            overlays = [
              rust-overlay.overlays.default
              (final: prev: {
                # We need >= 1.1.0 of cargo-sort, nixpkgs-stable publishes 1.0.9.
                cargo-sort = prev.rustPlatform.buildRustPackage {
                  pname = "cargo-sort";
                  version = "1.1.0";
                  src = prev.fetchFromGitHub {
                    owner = "DevinR528";
                    repo = "cargo-sort";
                    rev = "v1.1.0";
                    sha256 = "sha256-AUtue1xkhrhlF7PtqsCQ9rdhV0/0i85DWrp7YL9SAYk=";
                  };
                  cargoHash = "sha256-y6lLwk40hmFQKDU7sYz3+QQzdn5eGoEX7izmloK22dg=";
                };
              })
            ];
          };

          # Many of the SDKs packages share common build controls. This
          # helper function can be used to abstract any shared
          # configuration. Many of these helpers exist for each platform, and
          # this is the highest level one.
          mkRustPackage =
            pkgs: attrs:
            pkgs.rustPlatform.buildRustPackage (
              {
                version = "1.0.0";
                src = ./.;
                cargoLock = {
                  lockFile = ./Cargo.lock;
                  # Dependencies pulled straight from git need hashes for nix
                  # to compare to ensure reproducible builds
                  outputHashes = {
                    "passkey-0.2.0" = "sha256-J8RKMH2GFikqmYQNo5/Rr80zcKuZyWHPRy/Vbc1lAc0=";
                    "credential-exchange-types-0.1.0" = "sha256-K/YcQg+a5EBVqILr5eVMW0qHPjhDpyjvC5Sh/qeL+Cg=";
                  };
                };

                nativeBuildInputs = mkRustBuildInputs pkgs pkgs.stdenv.hostPlatform.config;

                # Opt in to linting, tests, and formatting.
                # We only run this on the default package to keep jobs speedy.
                doCheck = false;

                env = rustEnvVariables;
              }
              // attrs
            );

          # This recreates a lot of what `cargo cross` does, only without
          # containers. Cargo cross is a good reference to use if you're
          # experiencing unexpected behavior with Android builds!
          mkAndroidPackage =
            pkgs:
            {
              pname,
              target,
              targetDir,
            }:
            let
              # This seems fishy, right? Why specify x86 binaries instead of checking for ARM ones too?
              # You might be thinking "this won't work on my M Series Mac"
              # You are incorrect.
              #
              # These tools are x86_64 binaries but they're cross-compilers - they can generate code for other architectures
              # Android's official NDK distribution only provides x86_64 binaries for macOS, even when running on M1/M2 Macs
              # These x86_64 binaries will run fine on your M1/M2 Mac through Rosetta 2
              ndkHost = if pkgs.stdenv.isDarwin then "darwin-x86_64" else "linux-x86_64";
              ndkPath = "${mkAndroidSdk system}/share/android-sdk/ndk/27.0.11902837";
              toolchainPath = "${ndkPath}/toolchains/llvm/prebuilt/${ndkHost}";
              sysroot = "${toolchainPath}/sysroot";

              targetEnvName = builtins.replaceStrings [ "-" ] [ "_" ] target;
              targetEnvNameUpper = pkgs.lib.strings.toUpper targetEnvName;

              # Some compiler names have special cases ("armv7a")
              compilerPrefix =
                {
                  "aarch64-linux-android" = "aarch64-linux-android";
                  "armv7-linux-androideabi" = "armv7a-linux-androideabi";
                  "x86_64-linux-android" = "x86_64-linux-android";
                  "i686-linux-android" = "i686-linux-android";
                }
                .${target} or target;
            in
            mkRustPackage pkgs {
              inherit pname;
              env = {
                # Set environment variables android, clang, etc need
                ANDROID_SDK_ROOT = "${mkAndroidSdk system}/share/android-sdk";
                ANDROID_NDK_ROOT = ndkPath;
                CROSS_SYSROOT = sysroot;
                PATH = "${toolchainPath}/bin:${mkAndroidSdk system}/share/android-sdk/ndk/27.0.11902837/bin:$PATH";

                "CC_${targetEnvName}" = "${toolchainPath}/bin/${compilerPrefix}21-clang";
                "CXX_${targetEnvName}" = "${toolchainPath}/bin/${compilerPrefix}21-clang++";
                "AR_${targetEnvName}" = "${toolchainPath}/bin/llvm-ar";
                "RANLIB_${targetEnvName}" = "${toolchainPath}/bin/llvm-ranlib";
                "CARGO_TARGET_${targetEnvNameUpper}_LINKER" = "${toolchainPath}/bin/${compilerPrefix}21-clang";
                "BINDGEN_EXTRA_CLANG_ARGS_${targetEnvName}" = "--sysroot=${sysroot}";
                "DEP_Z_INCLUDE" = "${sysroot}/usr/include";
              };
              nativeBuildInputs = mkAndroidBuildInputs system pkgs target;
              buildPhase = ''
                cargo build -p bitwarden-uniffi --release --target ${target}
              '';
              installPhase = ''
                runHook preInstall
                mkdir -p $out/lib/android/${targetDir}
                cp target/${target}/release/libbitwarden_uniffi.so $out/lib/android/${targetDir}/
                runHook postInstall
              '';
            };
          mkSwiftPackage =
            pkgs:
            {
              pname,
              target,
              targetDir,
              sdk,
            }:
            let
              # Ensure xcode and the correct linkers are availible for clang to use
              xcodeenv = pkgs.callPackage "${pkgs.path}/pkgs/development/mobile/xcodeenv" { };
              xcodewrapper = xcodeenv.composeXcodeWrapper {
                versions = [ "16.2" ];
                xcodeBaseDir = "/Applications/Xcode.app";
              };
              iosLinkerWrapper = pkgs.writeScriptBin "ios-linker" ''
                #!${pkgs.bash}/bin/bash
                export DEVELOPER_DIR="/Applications/Xcode.app/Contents/Developer"
                exec xcrun --sdk ${sdk} clang "$@"
              '';
              iOSSDK = "/Applications/Xcode.app/Contents/Developer/Platforms/${
                if sdk == "iphonesimulator" then "iPhoneSimulator" else "iPhone"
              }.platform/Developer/SDKs/${if sdk == "iphonesimulator" then "iPhoneSimulator" else "iPhone"}.sdk";
            in
            mkRustPackage pkgs {
              inherit pname;
              nativeBuildInputs = [
                xcodewrapper
                iosLinkerWrapper
              ] ++ (mkRustBuildInputs pkgs target);
              __noChroot = true;
              __impure = true;
              # The rust-overlay has a tendency to override some of the
              # envioronment variables we need to build for iOS. For that
              # reason these variables are exported right in the buildPhase.
              #
              # They override a lot of incorrect redirections to nixpkgs xcode libraries,
              # ensuring that instead we use Xcode from the filesystem of the
              # building machine.
              buildPhase = ''
                export NIX_LDFLAGS=""
                # Point macOs, cc-rs and clang to the right xcode build libraries
                export DEVELOPER_DIR="/Applications/Xcode.app/Contents/Developer"
                export PATH="$DEVELOPER_DIR/usr/bin:$DEVELOPER_DIR/Toolchains/XcodeDefault.xctoolchain/usr/bin:$PATH"
                export IPHONEOS_DEPLOYMENT_TARGET="13.0"
                export RUSTFLAGS="-C link-arg=-Wl,-application_extension"
                # Use our wrapper script as the linker
                export CARGO_TARGET_${builtins.replaceStrings [ "-" ] [ "_" ] target}_LINKER="ios-linker"
                # Point to iOS SDK paths
                export SDKROOT=${iOSSDK}
                export DYLD_ROOT_PATH=${iOSSDK}
                # Configure compiler for iOS
                export CC_aarch64_apple_ios_sim="ios-sim-linker"
                export CC_${builtins.replaceStrings [ "-" ] [ "_" ] target}="ios-linker"
                export CFLAGS_aarch64_apple_ios_sim="-isysroot ${iOSSDK}"
                cargo build -p bitwarden-uniffi --target ${target} --release
              '';
              installPhase = ''
                runHook preInstall
                mkdir -p $out/lib/swift/${targetDir}
                cp target/${target}/release/libbitwarden_uniffi.a $out/lib/swift/${targetDir}
                runHook postInstall
              '';
            };

          # This function can generate a single nix package for one rust crate
          mkRustCrate =
            pkgs:
            { pname }:
            mkRustPackage pkgs {
              inherit pname;
              nativeBuildInputs = [
                pkgs.findutils
              ];
              buildPhase = ''
                cargo build -p ${pname} --release
              '';
              installPhase = ''
                runHook preInstall
                mkdir -p $out/lib/rust/${pname}
                find target/release -maxdepth 1 -type f -exec cp {} $out/lib/rust/${pname} \;
                runHook postInstall
              '';
            };

          # Pull in all the bitwarden crates from Cargo.toml
          rustCrates =
            let
              cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
              crateNames = builtins.filter (name: pkgs.lib.hasPrefix "bitwarden-" name) (
                builtins.attrNames cargoToml.workspace.dependencies
              );
            in
            crateNames;

          # Iterate over each detected crate and build a nix package for it
          rustCratePackages = pkgs.lib.listToAttrs (
            map (name: {
              inherit name;
              value = mkRustCrate pkgs {
                pname = name;
              };
            }) rustCrates
          );

          mkWasmPackage =
            pkgs:
            { pname }:
            let
              # gitRev is used for versioning the sdk
              gitRev = self.rev or "dirty";

              # Pin wasm-bindgen-cli version to what we have in Cargo.toml
              # Any amount of version mismatch between these two causes an error.
              wasm-bindgen-cli-0-2-100 = pkgs.rustPlatform.buildRustPackage {
                pname = "wasm-bindgen-cli";
                version = "0.2.100";
                src = pkgs.fetchCrate {
                  pname = "wasm-bindgen-cli";
                  version = "0.2.100";
                  sha256 = "sha256-3RJzK7mkYFrs7C/WkhW9Rr4LdP5ofb2FdYGz1P7Uxog=";
                };
                cargoHash = "sha256-tD0OY2PounRqsRiFh8Js5nyknQ809ZcHMvCOLrvYHRE=";
              };

              # We use webpack to compile js fallbacks of the wasm bindings.
              # This simple config gets that job done and is what is used by
              # the webpack-cli during builds.
              webpackConfig = pkgs.writeTextFile {
                name = "webpack.config.js";
                text = ''
                  const path = require('path');
                  module.exports = {
                    entry: './crates/bitwarden-wasm-internal/npm/bitwarden_wasm_internal_bg.js',
                    output: {
                      path: path.resolve(process.cwd(), 'crates/bitwarden-wasm-internal/npm'),
                      filename: 'bitwarden_wasm_internal_bg.bundle.js'
                    },
                    experiments: {
                      asyncWebAssembly: true,
                      topLevelAwait: true,
                    },
                    mode: 'production'
                  };
                '';
              };

              # This abstracts a few setup steps into a script that is run at
              # the beginning of builds.  When using `nix develop .#wasm`
              # `set-env` can also be run before debugging something like
              # wasm-bindgen.
              setupEnv = pkgs.writeShellScriptBin "setup-env" ''
                ln -sf ${webpackConfig} webpack.config.js
                mkdir -p crates/bitwarden-wasm-internal/npm
                echo ${gitRev} > crates/bitwarden-wasm-internal/npm/VERSION
              '';
            in
            mkRustPackage pkgs {
              inherit pname;

              nativeBuildInputs = with pkgs; [
                (rust-bin.stable.latest.default.override {
                  targets = [ "wasm32-unknown-unknown" ];
                })
                binaryen
                wasm-bindgen-cli-0-2-100
                nodePackages.prettier
                nodePackages.terser
                git
                nodePackages.webpack
                nodePackages.webpack-cli
                setupEnv
              ];

              # This is from build.sh
              # NOTE: CI uses wasm2js, but it has fallen out of date and doens't work with newer versions of rust.
              # This build swaps to using webpack for generating the js fallbacks.
              buildPhase = ''
                setup-env

                # Build wasm
                cargo build -p bitwarden-wasm-internal --target wasm32-unknown-unknown --release

                # Generate JS bindings
                wasm-bindgen --target bundler \
                --out-dir crates/bitwarden-wasm-internal/npm \
                ./target/wasm32-unknown-unknown/release/bitwarden_wasm_internal.wasm

                wasm-bindgen --target nodejs \
                --out-dir crates/bitwarden-wasm-internal/npm/node \
                ./target/wasm32-unknown-unknown/release/bitwarden_wasm_internal.wasm

                # Format JS files
                prettier --write ./crates/bitwarden-wasm-internal/npm

                # Optimize wasm size
                wasm-opt -Os \
                ./crates/bitwarden-wasm-internal/npm/bitwarden_wasm_internal_bg.wasm \
                -o ./crates/bitwarden-wasm-internal/npm/bitwarden_wasm_internal_bg.wasm

                # Use webpack-cli directly
                ${pkgs.nodePackages.webpack-cli}/bin/webpack-cli

                # Minify webpack's output with absolute path
                terser ./crates/bitwarden-wasm-internal/npm/bitwarden_wasm_internal_bg.bundle.js \
                -o ./crates/bitwarden-wasm-internal/npm/bitwarden_wasm_internal_bg.bundle.min.js
              '';

              installPhase = ''
                runHook preInstall
                mkdir -p $out/lib/wasm
                cp -r crates/bitwarden-wasm-internal/npm/* $out/lib/wasm
                runHook postInstall
              '';
            };

          # This function generates a nix package based on a configured rust check
          # This usually just means running some cargo command and generating logs
          mkCheck =
            pkgs:
            {
              pname,
              command,
              useNightly ? false,
              nativeBuildInputs ? [ ],
              ...
            }@attrs:
            let
              rustBin =
                if useNightly then pkgs.rust-bin.nightly.latest.default else pkgs.rust-bin.stable.latest.default;
            in
              mkRustPackage pkgs (attrs // {
              inherit pname;

              nativeBuildInputs = mkRustBuildInputs pkgs pkgs.stdenv.hostPlatform.config ++ nativeBuildInputs;

              env = {
                CARGO = "${rustBin}/bin/cargo";
                RUSTC = "${rustBin}/bin/rustc";
              };
              buildPhase = ''
                set -eo pipefail
                set -x
                mkdir -p $TMPDIR/logs
                {
                  ${command}
                } 2>&1 | tee $TMPDIR/logs/${pname}.log
                set +x
              '';
              installPhase = ''
                mkdir -p $out/logs
                cp -r $TMPDIR/logs/* $out/logs/
              '';
            });
        in
        # rustCratePackages gets each crate from [workspace.dependencies] in
        # Cargo.toml.  This means something like
        # ```
        # nix build .#bitwarden-api-api
        # ```
        # will build that particular crate for release.
        # You can build all crates at once with `nix build .#all-rust-crates`
        rustCratePackages
        // {
          build = mkCheck pkgs {
            pname = "build";
            command = "cargo build --release";
          };

          test = mkCheck pkgs {
            pname = "test";
            command = "cargo nextest run --release";
          };

          fmt = mkCheck pkgs {
            pname = "fmt";
            command = "cargo fmt --check";
            useNightly = true;
          };

          lint = mkCheck pkgs {
            pname = "lint";
            command = "cargo clippy --all-features --tests";
          };

          sort-workspaces = mkCheck pkgs {
            pname = "sort-workspaces";
            command = "cargo sort --workspace --check";
          };

          unused-deps = mkCheck pkgs {
            pname = "unused-deps";
            command = "cargo udeps --workspace --all-features";
            useNightly = true;
          };

          js-lint = mkCheck pkgs {
            pname = "js-lint";
            command = "npm run lint";
          };

          cloc = mkCheck pkgs {
            pname = "cloc";
            # In CI this runs `cloc --vcs, but in a nix build this is
            # unecassary because only the git files are in the nix store for
            # checking anyway. The .git directory is not even present.
            command = "${pkgs.cloc}/bin/cloc .";
          };

          # The memory tests only work on linux because of the gdp dependency.
          # It does some hacky stuff in the 
          memory-test =
            if pkgs.stdenv.isLinux then
              mkCheck pkgs {
                pname = "memory-test";
                command = ''
                  BASE_DIR="./crates/memory-testing"
                  mkdir -p $BASE_DIR/output
                  cargo build -p memory-testing --release
                  sudo ./target/release/capture-dumps ./target/release/memory-testing $BASE_DIR
                  ./target/release/analyze-dumps $BASE_DIR
                '';
                nativeBuildInputs = with pkgs; [ gdb sudo ];
              } // {
                __noChroot = true;
                __impure = true;
              }
            else
              pkgs.runCommand "memory-test-unsupported" { } ''
                mkdir -p $out/logs
                echo "Memory testing is only supported on Linux platforms" > $out/logs/memory-test.log
              '';

          wasm = mkWasmPackage pkgs {
            pname = "bitwarden-sdk-wasm";
          };

          android-aarch64 = mkAndroidPackage pkgs {
            pname = "bitwarden-sdk-uniffi-aarch64";
            target = "aarch64-linux-android";
            targetDir = "arm64-v8a";
          };

          android-armv7 = mkAndroidPackage pkgs {
            pname = "bitwarden-sdk-uniffi-armv7";
            target = "armv7-linux-androideabi";
            targetDir = "armeabi-v7a";
          };

          android-x86_64 = mkAndroidPackage pkgs {
            pname = "bitwarden-sdk-uniffi-x86_64";
            target = "x86_64-linux-android";
            targetDir = "x86_64";
          };

          android-i686 = mkAndroidPackage pkgs {
            pname = "bitwarden-sdk-uniffi-i686";
            target = "i686-linux-android";
            targetDir = "x86";
          };

          android-all = pkgs.symlinkJoin {
            name = "bitwarden-sdk-uniffi-android-all";
            paths = [
              self.packages.${system}.android-aarch64
              self.packages.${system}.android-armv7
              self.packages.${system}.android-x86_64
              self.packages.${system}.android-i686
            ];
          };

          android = mkRustPackage pkgs {
            pname = "bitwarden-sdk-android";

            nativeBuildInputs = mkAndroidLibraryBuildInputs system pkgs pkgs.stdenv.hostPlatform.config;

            buildInputs = [
              self.packages.${system}.android-all
            ];

            env = {
              GRADLE_USER_HOME = "$TMPDIR/.gradle";
              ANDROID_USER_HOME = "$TMPDIR/.android";
              ANDROID_HOME = "${mkAndroidSdk system}/share/android-sdk";
              GRADLE_OPTS = "-Dmaven.repo.local=${mkMavenRepo pkgs}";
            };

            # TODO: I'm not sure why we copy all the different android builds for
            # each architecture, but then only generate bindings from arm64-v8a.
            # Nonetheless: this is how CI does it right now.
            buildPhase = ''
              mkdir -p $out

              mkdir -p $TMPDIR/.gradle
              mkdir -p $TMPDIR/.android

              mkdir -p crates/bitwarden-uniffi/kotlin/sdk/src/main/jniLibs

              cp -r ${
                self.packages.${system}.android-all
              }/lib/android/* crates/bitwarden-uniffi/kotlin/sdk/src/main/jniLibs/

              cargo run -p uniffi-bindgen generate \
                crates/bitwarden-uniffi/kotlin/sdk/src/main/jniLibs/arm64-v8a/libbitwarden_uniffi.so \
                --library \
                --language kotlin \
                --no-format \
                --out-dir sdk/src/main/java

              cd crates/bitwarden-uniffi/kotlin
              echo "sdk.dir=${mkAndroidSdk system}/share/android-sdk" > local.properties

              ${pkgs.gradle_8}/bin/gradle :sdk:build --parallel
            '';

            installPhase = ''
              runHook preInstall
              mkdir -p $out/lib/android/
              cp sdk/build/outputs/aar/sdk-release.aar $out/lib/android
              cp -r sdk/src/main/jniLibs/* $out/lib/android
              runHook postInstall
            '';
          };

          swift-aarch64-sim = mkSwiftPackage pkgs {
            pname = "bitwarden-sdk-swift-aarch64-sim";
            target = "aarch64-apple-ios-sim";
            targetDir = "aarch64-apple-sim";
            sdk = "iphonesimulator";
          };

          swift-x86_64-ios = mkSwiftPackage pkgs {
            pname = "bitwarden-sdk-swift-x86_64-ios";
            target = "x86_64-apple-ios";
            targetDir = "x86_64-apple-ios";
            sdk = "iphonesimulator";
          };

          swift-aarch64-ios = mkSwiftPackage pkgs {
            pname = "bitwarden-sdk-swift-aarch64-ios";
            target = "aarch64-apple-ios";
            targetDir = "aarch64-apple-ios";
            sdk = "iphoneos";
          };

          swift-all = pkgs.symlinkJoin {
            name = "bitwarden-sdk-swift-all";
            __noChroot = true;
            __impure = true;
            paths = [
              self.packages.${system}.swift-aarch64-sim
              self.packages.${system}.swift-aarch64-ios
              self.packages.${system}.swift-x86_64-ios
            ];
            meta.platforms = pkgs.lib.platforms.darwin;
          };

          swift = mkRustPackage pkgs {
            pname = "bitwarden-sdk-swift";

            __noChroot = true;
            __impure = true;

            nativeBuildInputs = with pkgs; [
              libtool
              xcodebuild
            ];

            buildInputs = [
              self.packages.${system}.swift-aarch64-sim
              self.packages.${system}.swift-x86_64-ios
              self.packages.${system}.swift-aarch64-ios
            ];

            buildPhase = ''
              mkdir -p tmp/target/universal-ios-sim/release

              # Create universal library for simulator from both architectures
              lipo -create ${
                self.packages.${system}.swift-aarch64-sim
              }/lib/swift/aarch64-apple-sim/libbitwarden_uniffi.a \
              ${self.packages.${system}.swift-x86_64-ios}/lib/swift/x86_64-apple-ios/libbitwarden_uniffi.a \
              -output ./tmp/target/universal-ios-sim/release/libbitwarden_uniffi.a

              # Generate swift bindings (might need to build a dylib specifically for this)
              cargo run -p uniffi-bindgen generate \
              ${self.packages.${system}.swift-aarch64-sim}/lib/swift/aarch64-apple-sim/libbitwarden_uniffi.a \
                --library \
                --language swift \
                --no-format \
                --out-dir tmp/bindings

              # Set up Swift package structure
              mkdir -p Sources/BitwardenSdk
              mv ./tmp/bindings/*.swift ./Sources/BitwardenSdk/

              # Prepare headers for xcframework
              mkdir -p tmp/Headers
              mv ./tmp/bindings/*.h ./tmp/Headers/
              cat ./tmp/bindings/*.modulemap > ./tmp/Headers/module.modulemap

              # Build xcframework with device and simulator libraries
              /Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild -create-xcframework \
                -library ${
                  self.packages.${system}.swift-aarch64-ios
                }/lib/swift/aarch64-apple-ios/libbitwarden_uniffi.a \
                -headers ./tmp/Headers \
                -library ./tmp/target/universal-ios-sim/release/libbitwarden_uniffi.a \
                -headers ./tmp/Headers \
                -output ./BitwardenFFI.xcframework
            '';

            installPhase = ''
              runHook preInstall
              mkdir -p $out/lib/swift
              cp -r BitwardenFFI.xcframework $out/lib/swift
              cp -r Sources/BitwardenSdk $out/lib/swift
              runHook postInstall
              cp -r ${self.packages.${system}.swift-aarch64-ios}/lib/swift/* $out/lib/swift
              cp -r ${self.packages.${system}.swift-aarch64-sim}/lib/swift/* $out/lib/swift
              cp -r ${self.packages.${system}.swift-x86_64-ios}/lib/swift/* $out/lib/swift
            '';

            meta.platforms = pkgs.lib.platforms.darwin;
          };

          rustdoc = mkRustPackage pkgs {
            pname = "rustdoc";
            nativeBuildInputs = with pkgs; [
              (rust-bin.nightly.latest.default.override {
                extensions = [ "rust-src" ];
              })
            ];
            env = {
              RUSTDOCFLAGS = "--enable-index-page -Zunstable-options";
            };
            buildPhase = ''
              cargo doc --no-deps --all-features --document-private-items
            '';
            installPhase = ''
              runHook preInstall
              mkdir -p $out/doc
              cp -r target/doc/* $out/doc/
              runHook postInstall
            '';
          };

          crates = pkgs.symlinkJoin {
            name = "crates";
            paths = map (name: rustCratePackages.${name}) rustCrates;
          };

          builds = (pkgs.symlinkJoin ({
            name = "builds";
            paths = with self.packages.${system}; [
              crates
              wasm
              android
              rustdoc
            ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
              swift
            ];
          } // pkgs.lib.optionalAttrs pkgs.stdenv.isDarwin {
            __noChroot = true;
            __impure = true;
          }));


          checks = pkgs.symlinkJoin {
            name = "checks";
            paths = with self.packages.${system}; [
              build
              test
              fmt
              lint
              sort-workspaces
              unused-deps
              js-lint
              cloc
              memory-test
            ];
          };

          # You probably don't want to actually run this. It exists mostly to
          # test the build system as a whole, and for performance testing.
          #
          # Generally for development just running `nix build` to run the
          # checks is enough, or targetting a specific platform (crates,
          # wasm, swift, android) if you are having issues with a specific
          # build.
          everything = (pkgs.symlinkJoin ({
            name = "everything";
            paths = with self.packages.${system}; [
              checks
              builds
            ];
          } // pkgs.lib.optionalAttrs pkgs.stdenv.isDarwin {
            __noChroot = true;
            __impure = true;
          }));

          default = self.packages.${system}.checks;
        }
      );
      devShells = allSupportedSystems (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };
        in
        {
          default = pkgs.mkShell {
            nativeBuildInputs = with pkgs; [
              (rust-bin.stable.latest.default.override {
                extensions = [
                  "rust-src"
                  "rust-analyzer"
                  "clippy"
                ];
              })
              # see bacon.toml for our bacon configuration
              bacon
              # TODO: cargo-nextest is recommended by the README, but bacon.toml just uses cargo test
              cargo-nextest
            ];

            env = {
              RUST_BACKTRACE = 1;
            } // rustEnvVariables;

            shellHook = ''
              echo "Rust development environment loaded!"
              echo "Run 'bacon' to get started developing."
            '';
          };
        }
      );
    };
}
