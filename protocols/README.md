# Protocol models

[Verifpal](https://verifpal.com) models of SDK protocols. CI verifies every `*.vp` file here.

## Running locally

The only supported way to run Verifpal is the version pinned in the root `Cargo.toml`
(`[workspace.metadata.bin]`):

```sh
cargo install cargo-run-bin --locked --version 1.7.4
cargo bin verifpal verify protocols/<model>.vp
```

`cargo install verifpal`, Homebrew and AUR installs are not approved: they build or ship code we
have not pinned or reviewed.

## Updating Verifpal

Bump `rev` and `version` in the root `Cargo.toml` and in `support/verifpal/Cargo.toml`, then reseed
`support/verifpal/Cargo.lock` from upstream (see its [README](../support/verifpal/README.md)).
