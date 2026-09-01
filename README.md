# Bitwarden Internal SDK

This repository houses the internal Bitwarden SDKs. We also provide a public
[Secrets Manager SDK](https://github.com/bitwarden/sdk-sm).

> [!WARNING]
>
> The password manager SDK is not intended for public use and is not supported by Bitwarden at this
> stage. It is solely intended to centralize the business logic and to provide a single source of
> truth for the internal applications. As the SDK evolves into a more stable and feature-complete
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

## Integrating builds into client applications

`sdk-internal` changes can be integrated with clients in three progressive ways, each suited to a
different phase of development:

1. **[Local builds during development](#integrating-builds-into-client-applications-for-local-development)**:
   build the SDK on your machine and link it directly into a client checkout. This is the fastest
   inner loop for individual developer iteration developing on `clients` and `sdk-internal`
   together.
2. **[Unpublished SDK builds via client CI](#integrating-unpublished-sdk-builds-via-client-ci)**:
   have each client's CI build a client artifact against an unmerged `sdk-internal` branch. This
   works for QA or CI validation of the combined state before either side merges.
3. **[Published artifacts on `main`](#integrating-into-clients-from-published-artifacts)**: the
   merge-and-release path where `sdk-internal` publishes on merge to `main`, and each client picks
   up the new version through an automated PR.

## Integrating builds into client applications for local development

> [!TIP]
>
> **When do I use this?**
>
> Use local linking when you are actively developing SDK changes and want the fastest inner loop for
> iteration. Local links reflect uncommitted changes immediately, without pushing to GitHub or
> waiting for CI. It is not suitable for QA or CI validation, since the linked artifact only exists
> on your machine.

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
script. See [Licensing](#licensing) for details on why we have multiple packages and determine which
one(s) you need to build.

#### Linking

The web clients use NPM to install `sdk-internal` as a dependency. NPM offers a dedicated command
[`link`][npm-link] which can be used to temporarily replace the packages with a locally-built
version.

When building the web `sdk-internal` artifacts, you had the option to build the OSS or the
commercially-licensed version. You will need to adjust your `npm link` command according to which
one you built, and which one you intend to make available to the client application for your local
development.

| Desired client build           | Build script you ran          | SDK artifact built                                        | Link command                                                                                                                       | Result                                                               |
| ------------------------------ | ----------------------------- | --------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| OSS                            | `./build.sh`                  | Artifact with OSS-licensed code                           | `npm link ../sdk-internal/crates/bitwarden-wasm-internal/npm`                                                                      | SDK with OSS-licensed code linked to `clients`                       |
| Commercial (Bitwarden license) | `./build.sh && ./build.sh -b` | Artifact with **both** OSS and commercially-licensed code | `npm link ../sdk-internal/crates/bitwarden-wasm-internal/npm ../sdk-internal/crates/bitwarden-wasm-internal/bitwarden_license/npm` | SDK with both OSS and commercially-licensed code linked to `clients` |

Running `npm link` will restore any previously linked packages, so only the paths in the last run
command will be linked. When doing commercial development, always link **both** packages (as shown
above) so that changes to OSS types are also reflected in the client — linking only the
commercially-licensed package will leave OSS types stale.

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

## Integrating unpublished SDK builds via client CI

> [!TIP]
>
> **When do I use this?**
>
> Use a client CI build against pre-publish SDK artifacts when the `sdk-internal` change needs to be
> tested outside of a local developer's environment _before it lands in the `sdk-internal` `main`
> branch_.

Between [local linking](#integrating-builds-into-client-applications-for-local-development) and
[published artifacts on `main`](#integrating-into-clients-from-published-artifacts), each client
repository provides a way for client CI (and its resulting artifacts) to run against SDK artifacts
produced by an `sdk-internal` feature-branch CI run, without the SDK being published and consumed as
a dependency.

### Web clients

The `bitwarden/clients` build workflows expose an `sdk_branch` `workflow_dispatch` input:

- [`build-web.yml`](https://github.com/bitwarden/clients/actions/workflows/build-web.yml)
- [`build-browser.yml`](https://github.com/bitwarden/clients/actions/workflows/build-browser.yml)
- [`build-desktop.yml`](https://github.com/bitwarden/clients/actions/workflows/build-desktop.yml)
- [`build-cli.yml`](https://github.com/bitwarden/clients/actions/workflows/build-cli.yml)

Manually dispatch the appropriate build workflow against the desired `clients` branch and set
`sdk_branch` to your `sdk-internal` feature branch. The workflow downloads the latest successful
`build-wasm-internal.yml` artifacts from that branch and npm-links them into the client build,
producing a CI artifact that combines both in-progress branches without any publish step.

### Android

Every push to `sdk-internal` publishes a Maven artifact to GitHub Packages (see the Publish step in
[`build-android.yml`](./.github/workflows/build-android.yml)). To integrate a feature-branch build
into the Android client, manually dispatch that workflow against your feature branch with
`update-android-repo=true`, which triggers
[`sdlc-sdk-update.yml`](https://github.com/bitwarden/android/actions/workflows/sdlc-sdk-update.yml)
in `bitwarden/android` to open a PR bumping the SDK to that feature-branch version.

### iOS

Dispatch [`build-swift.yml`](./.github/workflows/build-swift.yml) on your feature branch to produce
xcframework artifacts, then manually dispatch
[`release-swift.yml`](./.github/workflows/release-swift.yml) with:

- `build-run-id`: the run ID of your feature-branch `build-swift.yml` run
- `sdk-swift-branch-name`: a non-`unstable` branch on `bitwarden/sdk-swift`
- `update-ios-repo`: `true` to trigger the iOS client update workflow with the resulting version

## Integrating into clients from published artifacts

> [!TIP]
>
> **When do I use this?**
>
> Use published artifacts when `sdk-internal` changes are either ready to ship into client
> production releases, or are flagged to allow testing in the clients `main`.

The process for integrating SDK changes into clients varies based on the client, as the method by
which the `sdk-internal` package is consumed differs.

> [!WARNING]
>
> **BREAKING CHANGES** require tight coordination between `sdk-internal` and the consuming client
> repo. See [Handling breaking SDK changes](#handling-breaking-sdk-changes) for the full workflow.

### What happens when an SDK PR merges to `main`

Merging an `sdk-internal` PR to `main` triggers a chain of automation across the SDK, deploy, and
client repositories:

1. The
   [publish workflow](https://github.com/bitwarden/deploy/blob/main/.github/workflows/publish-wasm-internal.yml)
   (internal access only) in the `deploy` repo publishes the OSS and commercial npm packages with a
   version of the form `{SemanticVersion}-main.{actionRunNumber}` (e.g., `0.1.0-main.470`).
2. The
   [SDK Update workflow](https://github.com/bitwarden/clients/tree/main/.github/workflows/sdk-update.yml)
   in `bitwarden/clients` opens or updates an automated PR that bumps `@bitwarden/sdk-internal` and
   `@bitwarden/commercial-sdk-internal` on client `main` to the newly published version.
3. The [Android](./.github/workflows/build-android.yml) and
   [iOS](./.github/workflows/build-swift.yml) build workflows publish mobile artifacts and trigger
   corresponding SDK update workflows in `bitwarden/android` and `bitwarden/ios`.

The client auto-PR is a **rolling update**: it stays open until merged and refreshes to the latest
published SDK version on each subsequent `sdk-internal` merge. Your SDK change may therefore ride
into `clients` bundled with other teams' SDK changes.

### Downstream impact of an SDK merge and client version bump

- **Other client feature branches** built against an older SDK version pick up your change when they
  merge `main` into their branch or manually run the "SDK Update" workflow. Non-breaking changes are
  absorbed transparently, but breaking changes surface as build failures on their branch and require
  adjustment.
- **Leaving a breaking-change window open blocks everyone.** Once an SDK breaking change lands on
  `main`, the client auto-PR fails to build — **blocking every other team's SDK-update PR from
  merging to client `main` until the client-side fix ships**. This is why breaking changes require a
  client PR ready to merge before the SDK PR merges.

### Handling breaking SDK changes

When an `sdk-internal` PR includes API breaking changes, the
[Breaking Change Detection](./.github/workflows/detect-breaking-changes.yml) workflow will flag it
on the PR by running client builds against the SDK branch and commenting the results. Breaking
changes require tighter coordination than other changes because once the SDK merges to `main`,
client `main` cannot build against it until the consuming client PR ships, and that open window
blocks every other team's SDK-update PR (see
[Downstream impact of an SDK merge and client version bump](#downstream-impact-of-an-sdk-merge-and-client-version-bump)).

Recommended sequence:

1. **Develop the SDK change** on a feature branch. Prepare the corresponding client change on a
   `clients` feature branch, using
   [local linking](#integrating-builds-into-client-applications-for-local-development) so the client
   build compiles against your in-progress SDK.
2. **Get the client PR reviewed and approved** so it's ready to merge. Do not merge it yet — the SDK
   version it consumes doesn't exist in npm until step 3.
3. **Merge the `sdk-internal` PR.** This triggers the publish workflow (see
   [What happens when an SDK PR merges to `main`](#what-happens-when-an-sdk-pr-merges-to-main)) and
   opens or updates the client auto-PR. The auto-PR will fail to build until step 6 lands. This is
   the breaking-change window.
4. **Bump the SDK on your client feature branch** by manually running the
   [SDK Update workflow](https://github.com/bitwarden/clients/actions/workflows/sdk-update.yml)
   against your feature branch: enter the published SDK version (see
   [Finding the published SDK version](#finding-the-published-sdk-version)) and your feature branch
   as the base.

   ![Manual workflow run of SDK Update targeting a clients feature branch](manual_workflow_run.png)

   The workflow only edits `package.json` and runs `npm install`, so you can make those edits by
   hand and commit them to your feature branch directly when the automation isn't a fit (e.g.
   bundling the SDK bump into a larger client commit).

5. **Merge the SDK bump PR into your client feature branch.** Because this adds new commits to the
   client PR, branch protection will dismiss the earlier approval. Re-request review and get the
   client PR approved again.
6. **Merge the client feature branch to `main`.** This closes the breaking-change window: the client
   auto-PR will now build clean and all other teams' pending SDK-update PRs unblock.

This describes the flow for web clients. Mobile clients follow the same pattern with their
respective SDK update workflows (see [Mobile clients](#mobile-clients)).

### Web clients

For our web clients, the `sdk-internal` packages for our OSS- and commercially-licensed SDK versions
with their WebAssembly bindings are published to npm at:

- https://www.npmjs.com/package/@bitwarden/sdk-internal and
- https://www.npmjs.com/package/@bitwarden/commercial-sdk-internal

See [Licensing](#licensing) for details on why we have multiple packages.

These npm packages are referenced as
[dependencies](https://github.com/bitwarden/clients/blob/main/package.json) in our `clients` repo.

When an SDK update merges to `sdk-internal` `main` branch, an auto-generated PR will open - or
update if already open - to bump the SDK version on `clients`. This PR is the recommended and
easiest way to integrate your changes into `clients`.

> [!TIP]
>
> <a id="finding-the-published-sdk-version"></a>**Finding the published SDK version.** After your
> `sdk-internal` PR merges, find the version that was published as follows:
>
> 1. Open the
>    [publish workflow](https://github.com/bitwarden/deploy/actions/workflows/publish-wasm-internal.yml)
>    in the `deploy` repo (internal access only).
> 2. Find the workflow run whose commit SHA matches the merge commit of your `sdk-internal` PR (the
>    run title includes the commit message).
> 3. Open that run and read the **Summary** tab. The published version is printed there in the
>    `{SemanticVersion}-main.{actionRunNumber}` format shown above (for example, `0.1.0-main.470`).

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

- [`bitwarden-api-api`](./crates/bitwarden-api-api/README.md): For the `Api` service that contains
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
> Use the [workflow](#updating-bindings-after-a-server-api-change) to make any merged binding
> changes. Running the scripts below can be helpful during local development, but please ensure that
> any changes to the bindings in `bitwarden-api-api` and `bitwarden-api-identity` are **not**
> checked into any pull request.

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

This project uses customized templates that live in the `support/openapi-template` directory. These
templates resolve some outstanding issues we've experienced with the Rust generator. But we strive
towards modifying the templates as little as possible to ease future upgrades.

> [!NOTE]
>
> If you don't have the nightly toolchain installed, the `build-api.sh` script will install it for
> you.

## Licensing

The Bitwarden internal SDK includes both OSS- and commercially-licensed code. This allows shared
code to exist in our SDK to support commercially-licensed (also known as Bitwarden-licensed)
clients.

The OSS-licensed packages that are published from `sdk-internal` include only code licensed under
the [GPL](./LICENSE_GPL.txt) license. The commercially-licensed packages that are published from
`sdk-internal` include the OSS-licensed code, as well as code that is licensed under our
[commercial](./LICENSE_SDK.txt) license.

If you are developing in a client that needs both licensing models, you should be aware of the two
and ensure that they are both updated when integrating new SDK changes into the client application.

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

### Running the checks

```
npm run lint           # run every check (check-only, matches CI)
npm run lint:fix       # auto-fix where supported, then run the rest

# Run a single check:
npm run lint -- --only fmt
npm run lint -- --only clippy
```

The list of available checks: `fmt`, `clippy`, `sort`, `udeps`, `dylint`, `doc`, `prettier`,
`dep-ownership`, `cargo-lock`.

The command is implemented in [scripts/lint.sh](./scripts/lint.sh) and mirrors
[.github/workflows/lint.yml](./.github/workflows/lint.yml), so a local pass means CI will pass.

### Installation

Binary cargo tools (cargo-sort, cargo-udeps, cargo-dylint, etc.) are pinned in the root `Cargo.toml`
under `[workspace.metadata.bin]` and installed lazily by
[`cargo-run-bin`](https://crates.io/crates/cargo-run-bin), so dev and CI versions stay in sync.
Bootstrap once:

```bash
cargo install cargo-run-bin --locked
```

After that, `npm run lint` (or `scripts/lint.sh` directly) handles installation of any missing tool
on first invocation. The underlying tools are:

- Nightly [cargo fmt](https://github.com/rust-lang/rustfmt) and
  [cargo udeps](https://github.com/est31/cargo-udeps)
- [rust clippy](https://github.com/rust-lang/rust-clippy)
- [cargo dylint](https://github.com/trailofbits/dylint)
- [cargo sort](https://github.com/DevinR528/cargo-sort)
- [prettier](https://github.com/prettier/prettier)

If `cargo-run-bin` itself is missing locally, `npm run lint` will tell you how to install it.

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
