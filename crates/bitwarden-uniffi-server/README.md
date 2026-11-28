# Bitwarden UniFFI Server

UniFFI bindings of the SDK for the Bitwarden server (.NET). Separate from `bitwarden-uniffi`, so the
mobile client surface does not leak into the server.

C# bindings are generated in [dotnet-extensions](https://github.com/bitwarden/dotnet-extensions)
with [uniffi-bindgen-cs](https://github.com/NordSecurity/uniffi-bindgen-cs) in library mode, from
the `cdylib` built here:

```bash
cargo build -p bitwarden-uniffi-server --release
uniffi-bindgen-cs --library target/release/libbitwarden_uniffi_server.so \
  --config crates/bitwarden-uniffi-server/uniffi.toml --out-dir <out>
```

The `uniffi-bindgen-cs` version must target the `uniffi` version pinned in the workspace.
