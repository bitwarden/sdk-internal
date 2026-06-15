# Bitwarden Internal SDK

This repository houses the internal Bitwarden SDKs. We also provide a public [Secrets Manager SDK](https://github.com/bitwarden/sdk-sm).

> [!WARNING]
> 
> The password manager SDK is not intended for public use and is not supported by Bitwarden at this
> stage. It is solely intended to centralize the business logic and to provide a single source of
> truth for the internal applications. As the SDK evolves into a more stable and feature complete
> state we will re-evaluate the possibility of publishing stable bindings for the public.
> **The
> password manager interface is unstable and will change without warning.**

## Crates

The project is structured as a monorepo using cargo workspaces. Some of the more noteworthy crates are:

- [`bitwarden-api-api`](./crates/bitwarden-api-api): Auto-generated API bindings for the API server.
- [`bitwarden-api-identity`](./crates/bitwarden-api-identity): Auto-generated API bindings for the Identity server.
- [`bitwarden-core`](./crates/bitwarden-core): The core functionality consumed by the other crates.
- [`bitwarden-crypto`](./crates/bitwarden-crypto): Crypto library.
- [`bitwarden-wasm-internal`](./crates/bitwarden-wasm-internal): WASM bindings for the internal SDK.
- [`bitwarden-uniffi`](./crates/bitwarden-uniffi): Mobile bindings for swift and kotlin using [UniFFI](https://github.com/mozilla/uniffi-rs/).

## Status of Rust-based Bitwarden CLI

The Rust-based Bitwarden CLI is currently under development and is intended to eventually replace the JS-based Bitwarden CLI. Contributions to this effort are welcome.

## Requirements

- [Rust](https://www.rust-lang.org/tools/install) latest stable version
- (preferably installed via [rustup](https://rustup.rs/)).
- NodeJS and NPM.

## Setup instructions

1. Clone the repository:
```bash
 git clone https://github.com/bitwarden/sdk-internal.git
cd sdk-internal
```
2. Install the dependencies:
```bash
 npm ci
```

## Building

Run the following command:
```bash
cargo build
```

### Special considerations for Windows on ARM

For Windows on ARM, you will need the following in your `PATH`:

- [Python](https://www.python.org)
- [Clang](https://clang.llvm.org)
- We recommend installing this via the [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022)

## Integrating builds into client applications for local development

Integrating the SDK into client applications for local development requires two steps:

1. Building `sdk-internal` with bindings specific to the client application, and
2. Linking the build with your client for consumption there.

The instructions are different depending on the client that will be consuming the SDK.

> [!NOTE]
> 
> These instructions assume a directory structure similar to:
> 
> ```text
> sdk-internal/
> clients/
> ios/
> android/
> ```
> 
> If your repository directory structure differs you will need to adjust the commands accordingly.

### Web clients

#### Building

Build the SDK to expose WASM bindings, which will be consumed by our web clients, by following the instructions in [`crates/bitwarden-wasm-internal`](https://github.com/bitwarden/sdk-internal/tree/main/crates/bitwarden-wasm-internal).

After completing these instructions, you'll have built an SDK artifact that includes either OSS-licensed code, or both OSS- and commercially-licensed code, based on your choice of build script. See [Licensing](#licensing) for details on why we have multiple packages and determine which one(s) you need to build.

#### Linking

The web clients use NPM to install `sdk-internal` as a dependency. NPM offers a dedicated command [`link`][npm-link] which can be used to temporarily replace the packages with a locally-built version.

When building the web `sdk-internal` artifacts, you had the option to build the OSS or the commercially-licensed version. You will need to adjust your `npm link` command according to which one you built, and which one you intend to make available to the client application for your local development.

| Desired client build | Build script you ran | SDK artifact built | Link command | Result |
| ------------------------------ | ----------------------------- | --------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| OSS | `./build.sh` | Artifact with OSS-licensed code | `npm link ../sdk-internal/crates/bitwarden-wasm-internal/npm` | SDK with OSS-licensed code linked to `clients` |
| Commercial (Bitwarden license) | `./build.sh && ./build.sh -b` | Artifact with **both** OSS an