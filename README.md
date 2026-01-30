# Bitwarden Internal SDK

This repository houses the internal Bitwarden SDKs. We also provide a public
[Secrets Manager SDK](https://github.com/bitwarden/sdk-sm).

> [!WARNING]
>
> The password manager SDK is not intended for public use and is not supported by Bitwarden at this
> stage. It is solely intended to centralize the business logic and to provide a single source of
> truth for the internal applications. As the SDK evolves into a more stable and feature complete
> state we will re-evaluate the possibility of publishing stable bindings for the public. **The
> password manager interface is unstable and will change without warning.**

## Crates

The project is structured as a monorepo using cargo workspaces. Some of the more noteworthy crates
are:

- [`bitwarden-api-api`](./crates/bitwarden-api-api): Auto-generated API bindings for the API server.
- [`bitwarden-api-identity`](./crates/bitwarden-api-identity): Auto-generated API bindings for the
  Identity server.
- [`bitwarden-core`](./crates/bitwarden-core): The core functionality consumed by the other crates.
- [`bitwarden-crypto`](./crates/bitwarden-crypto): Crypto library.
- [`bitwarden-wasm-internal`](./crates/bitwarden-wasm-internal): WASM bindings for the internal SDK.
- [`bitwarden-uniffi`](./crates/bitwarden-uniffi): Mobile bindings for swift and kotlin using
  [UniFFI](https://github.com/mozilla/uniffi-rs/).

## Requirements

- [Rust](https://www.rust-lang.org/tools/install) latest stable version - (preferably installed via
  [rustup](https://rustup.rs/)).
- NodeJS and NPM.

## Setup instructions

1.  Clone the repository:

    ```bash
    git clone https://github.com/bitwarden/sdk-internal.git
    cd sdk-internal
    ```

2.  Install the dependencies:

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
  - We recommend installing this via the
    [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022)

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

Build the SDK to expose WASM bindings, which will be consumed by our web clients, by following the
instructions in
[`crates/bitwarden-wasm-internal`](https://github.com/bitwarden/sdk-internal/tree/main/crates/bitwarden-wasm-internal).

After completing these instructions, you'll have built an SDK artifact that includes either
OSS-licensed code, or both OSS- and commercially-licensed code, based on your choice of build
script.

#### Linking

The web clients use NPM to install `sdk-internal` as a dependency. NPM offers a dedicated command
[`link`][npm-link] which can be used to temporarily replace the packages with a locally-built
version.

When building the web `sdk-internal` artifacts, you had the option to build the OSS or the
commercially-licensed version. You will need to adjust your `npm link` command according to which
one you built, and which one you intend to make available to the client application for your local
development.

| I want to...                                                   | Build script you ran | SDK artifact built                                        | Link command                                                                    | Result                                                               |
| -------------------------------------------------------------- | -------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| Develop in clients using OSS-licensed code in the SDK          | `./build.sh`         | Artifact with OSS-licensed code                           | `npm link ../sdk-internal/crates/bitwarden-wasm-internal/npm`                   | SDK with OSS-licensed code linked to `clients`                       |
| Develop in clients using commercially-licensed code in the SDK | `./build.sh -b`      | Artifact with **both** OSS and commercially-licensed code | `npm link ../sdk-internal/crates/bitwarden-wasm-internal/bitwarden_license/npm` | SDK with both OSS and commercially-licensed code linked to `clients` |

Keep in mind that running `npm link` will restore any previously linked packages, so only the paths
in the last run command will be linked.

> [!WARNING]
>
> Running `npm ci` or `npm install` will replace the linked packages with the published version.

### Android

#### Building

Build the SDK to expose Kotlin bindings through UniFFI, which will be consumed by our Android mobile
app. Follow the instructions in
[`crates/bitwarden-uniffi/kotlin`](https://github.com/bitwarden/sdk-internal/tree/main/crates/bitwarden-uniffi/kotlin).

#### Linking

1. Build and publish the SDK to the local Maven repository:

   ```bash
   ../sdk-internal/crates/bitwarden-uniffi/kotlin/publish-local.sh
   ```

2. Set the user property `localSdk=true` in the `user.properties` file.

### iOS

#### Building

Build the SDK to expose iOS bindings through UniFFI, which will be consumed by our iOS mobile app.
Follow the instructions in
[`crates/bitwarden-uniffi/swift`](https://github.com/bitwarden/sdk-internal/tree/main/crates/bitwarden-uniffi/swift).

#### Linking

Run the bootstrap script with the `LOCAL_SDK` environment variable set to true in order to use the
local SDK build:

```bash
LOCAL_SDK=true ./Scripts/bootstrap.sh
```

## Integrating into clients from published artifacts

In addition to
[linking to local builds](#integrating-builds-into-client-applications-for-local-development) during
development, you will need to be able to integrate your `sdk-internal` changes into published
artifacts.

The process for doing so varies based on the client, as the method by which the `sdk-internal`
package is consumed differs.

### Web clients

For our web clients, the `sdk-internal` package with its WebAssembly bindings is published to npm at
https://www.npmjs.com/package/@bitwarden/sdk-internal, and this npm package is referenced as a
[dependency](https://github.com/bitwarden/clients/blob/main/package.json) in our `clients` repo.

Every commit to `main` in `sdk-internal` will trigger a
[publish](https://github.com/bitwarden/sdk-internal/blob/main/.github/workflows/publish-wasm-internal.yml)
of this package, with a version as follows:

```
{SemanticVersion}-main.{actionRunNumber}
```

For example:

```
0.1.0-main.470
```

> [!TIP]
>
> To see what version is published to `npm` for a given publish action, you can check the Summary of
> the publish action in Github.

When you have completed development of changes in the SDK and need to reference them in the client
application, you can:

1. Merge the `sdk-internal` pull request. This will trigger a publish of the latest changes to npm.
2. Update the version of the `sdk-internal` dependency in `clients` to reference this version. You
   can do this either:

- By updating to the latest version using `npm install @bitwarden/sdk-internal@latest`, or
- By referencing the specific `sdk-internal` published version, using
  `npm install @bitwarden/sdk-internal@{version}`.

3. Open a `clients` pull request to merge the client application changes that include this new
   `sdk-internal` version.

### Mobile clients

The iOS and Android applications use an automated, reactive approach to integrating `sdk-internal`
changes into their repositories.

When you need to integrate `sdk-internal` changes into the iOS or Android applications, you should
use the automatically-generated pull requests for each repository:

| Client  | SDK workflow                                                                            | Client workflow                                                            |
| ------- | --------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| Android | https://github.com/bitwarden/sdk-internal/blob/main/.github/workflows/build-android.yml | https://github.com/bitwarden/android/actions/workflows/sdlc-sdk-update.yml |
| iOS     | https://github.com/bitwarden/sdk-internal/blob/main/.github/workflows/build-swift.yml   | https://github.com/bitwarden/ios/actions/workflows/sdlc-sdk-update.yml     |

## Server API Bindings

We auto-generate the server bindings using
[openapi-generator](https://github.com/OpenAPITools/openapi-generator), which creates Rust bindings
from the server OpenAPI specifications. These bindings are
[regularly updated](https://github.com/bitwarden/sdk-internal/actions/workflows/update-api-bindings.yml)
to ensure they stay in sync with the server.

The bindings are exposed as multiple crates, one for each backend service:

- [`bitwarden-api-api`](./crates//bitwarden-api-api/README.md): For the `Api` service that contains
  most of the server side functionality.
- [`bitwarden-api-identity`](./crates/bitwarden-api-identity/README.md): For the `Identity` service
  that is used for authentication.

When performing any API calls the goal is to use the generated bindings as much as possible. This
ensures any changes to the server are accurately reflected in the SDK. The generated bindings are
stateless, and always expects to be provided a `Configuration` instance. The SDK exposes these under
the `get_api_configurations` function on the `Client` struct.

You should not expose the request and response models of the auto-generated bindings and should
instead define and use your own models. This ensures the server request / response models are
decoupled from the SDK models and allows for easier changes in the future without breaking backwards
compatibility.

We recommend using either the `From` or `TryFrom` conversion traits depending on if the conversion
requires error handling or not. Below are two examples of how this can be done:

```rust
# use bitwarden_crypto::EncString;
# use serde::{Serialize, Deserialize};
# use serde_repr::{Serialize_repr, Deserialize_repr};
#
# #[derive(Serialize, Deserialize, Debug, Clone)]
# struct LoginUri {
#     pub uri: Option<EncString>,
#     pub r#match: Option<UriMatchType>,
#     pub uri_checksum: Option<EncString>,
# }
#
# #[derive(Clone, Copy, Serialize_repr, Deserialize_repr, Debug, PartialEq)]
# #[repr(u8)]
# pub enum UriMatchType {
#     Domain = 0,
#     Host = 1,
#     StartsWith = 2,
#     Exact = 3,
#     RegularExpression = 4,
#     Never = 5,
# }
#
# #[derive(Debug)]
# struct VaultParseError;
#
impl TryFrom<bitwarden_api_api::models::CipherLoginUriModel> for LoginUri {
    type Error = VaultParseError;

    fn try_from(uri: bitwarden_api_api::models::CipherLoginUriModel) -> Result<Self, Self::Error> {
        Ok(Self {
            uri: EncString::try_from_optional(uri.uri)
                .map_err(|_| VaultParseError)?,
            r#match: uri.r#match.map(|m| m.into()),
            uri_checksum: EncString::try_from_optional(uri.uri_checksum)
                .map_err(|_| VaultParseError)?,
        })
    }
}

impl From<bitwarden_api_api::models::UriMatchType> for UriMatchType {
    fn from(value: bitwarden_api_api::models::UriMatchType) -> Self {
        match value {
            bitwarden_api_api::models::UriMatchType::Domain => Self::Domain,
            bitwarden_api_api::models::UriMatchType::Host => Self::Host,
            bitwarden_api_api::models::UriMatchType::StartsWith => Self::StartsWith,
            bitwarden_api_api::models::UriMatchType::Exact => Self::Exact,
            bitwarden_api_api::models::UriMatchType::RegularExpression => Self::RegularExpression,
            bitwarden_api_api::models::UriMatchType::Never => Self::Never,
        }
    }
}
```

### Updating bindings after a server API change

When the API exposed by the server changes, new bindings will need to be generated to reflect this
change for consumption in the SDK. Examples of such changes include adding new fields to server
request / response models, removing fields from models, or changing types of models.

A GitHub workflow exists to
[update the API bindings](https://github.com/bitwarden/sdk-internal/actions/workflows/update-api-bindings.yml).
This workflow should always be used to merge any binding changes to `main`, to ensure that there are
not conflicts with the auto-generated bindings in the future. Binding changes should **not** be
included as a part of the PR to consume them.

There are two ways to run the workflow:

1. Manually run the `Update API Bindings`
   [workflow](https://github.com/bitwarden/sdk-internal/actions/workflows/update-api-bindings.yml)
   in the `sdk-internal` repo. You can choose whether to update the bindings for the API, Identity,
   or both. You will likely only need to update the API bindings for the majority of changes.

2. Wait for an automatic binding update to run, which is scheduled every 2 weeks. This update will
   generate bindings for both API and Identity and create two PRs.

A suggested workflow for incorporating server API changes into the SDK would be:

1. Make changes in `server` repo to expose the new API.
2. Merge `server` changes to `main`.
3. Trigger the `Update API Bindings` workflow in `sdk-internal` to open a pull request with the
   updated API bindings.
4. Review and merge that pull request to `sdk-internal` `main` branch.
5. Pull in `sdk-internal` `main` into your feature branch for SDK work.
6. Consume new API models in SDK code.

#### Local binding updates

> [!IMPORTANT]
>
> Use the [workflow](#updating-bindings-after-a-server-api-change) to make any merged
> binding changes. Running the scripts below can be helpful during local development, but please
> ensure that any changes to the bindings in `bitwarden-api-api` and `bitwarden-api-identity` are
> **not** checked into any pull request.

In order to update the bindings locally, we first need to build the internal Swagger documentation.
This code should not be directly modified. Instead use the instructions below to generate Swagger
documents and use these to generate the OpenApi bindings.

#### Swagger generation

The first step is to generate the Swagger documents from the root of the
[server repository](https://github.com/bitwarden/server).

```bash
pwsh ./dev/generate_openapi_files.ps1
```

#### OpenApi Generator

To generate a new version of the bindings, run the following script from the root of the SDK
project. This requires a Java Runtime Environment, and also assumes the repositories `server` and
`sdk-internal` have the same parent directory.

```bash
./support/build-api.sh
```

This project uses customized templates that live in the `support/openapi-templates` directory. These
templates resolve some outstanding issues we've experienced with the Rust generator. But we strive
towards modifying the templates as little as possible to ease future upgrades.

> [!NOTE]
>
> If you don't have the nightly toolchain installed, the `build-api.sh` script will install it for
> you.

## Developer tools

This project recommends the use of certain developer tools and includes configurations for them to
make developers' lives easier. The use of these tools is optional, and they might require a separate
installation step.

The list of developer tools is:

- `Visual Studio Code`: We provide a recommended extension list which should show under the
  `Extensions` tab when opening this project with the editor. We also offer a few launch settings
  and tasks to build and run the SDK
- `bacon`: This is a CLI background code checker. We provide a configuration file with some of the
  most common tasks to run (`check`, `clippy`, `test`, `doc` - run `bacon -l` to see them all). This
  tool needs to be installed separately by running `cargo install bacon --locked`.
- `nexttest`: This is a new and faster test runner, capable of running tests in parallel and with a
  much nicer output compared to `cargo test`. This tool needs to be installed separately by running
  `cargo install cargo-nextest --locked`. It can be manually run using
  `cargo nextest run --all-features`

## Formatting & Linting

This repository uses various tools to check formatting and linting before it's merged. It's
recommended to run the checks before submitting a PR.

### Installation

Please see the [lint.yml](./.github/workflows/lint.yml) file, for example, installation commands and
versions. Here are the cli tools we use:

- Nightly [cargo fmt](https://github.com/rust-lang/rustfmt) and
  [cargo udeps](https://github.com/est31/cargo-udeps)
- [rust clippy](https://github.com/rust-lang/rust-clippy)
- [cargo dylint](https://github.com/trailofbits/dylint)
- [cargo sort](https://github.com/DevinR528/cargo-sort)
- [prettier](https://github.com/prettier/prettier)

### Checks

To verify if changes need to be made, here are examples for the above tools:

```
export RUSTFLAGS="-D warnings"

cargo +nightly fmt --check
cargo +nightly udeps --workspace --all-features
cargo clippy --all-features --all-targets
cargo dylint --all -- --all-features --all-targets
cargo sort --workspace --grouped --check
npm run lint
```

## Documentation

Please refer to our [Contributing Docs](https://contributing.bitwarden.com/) for
[architectural documentation](https://contributing.bitwarden.com/architecture/sdk/).

You can also browse the latest published documentation:

- [docs.rs](https://docs.rs/bitwarden/latest/bitwarden/) for the public SDK.
- Or for developers of the SDK, view the internal
  [API documentation](https://sdk-api-docs.bitwarden.com/bitwarden_core/index.html) which includes
  private items.

## Contribute

Code contributions are welcome! Please commit any pull requests against the `main` branch. Learn
more about how to contribute by reading the
[Contributing Guidelines](https://contributing.bitwarden.com/contributing/). Check out the
[Contributing Documentation](https://contributing.bitwarden.com/) for how to get started with your
first contribution.

Security audits and feedback are welcome. Please open an issue or email us privately if the report
is sensitive in nature. You can read our security policy in the [`SECURITY.md`](SECURITY.md) file.
We also run a program on [HackerOne](https://hackerone.com/bitwarden).

No grant of any rights in the trademarks, service marks, or logos of Bitwarden is made (except as
may be necessary to comply with the notice requirements as applicable), and use of any Bitwarden
trademarks must comply with
[Bitwarden Trademark Guidelines](https://github.com/bitwarden/server/blob/main/TRADEMARK_GUIDELINES.md).

## We're Hiring!

Interested in contributing in a big way? Consider joining our team! We're hiring for many positions.
Please take a look at our [Careers page](https://bitwarden.com/careers/) to see what opportunities
are currently open as well as what it's like to work at Bitwarden.

[npm-link]: https://docs.npmjs.com/cli/v9/commands/npm-link
[sm]: https://bitwarden.com/products/secrets-manager/
[pm]: https://bitwarden.com/
