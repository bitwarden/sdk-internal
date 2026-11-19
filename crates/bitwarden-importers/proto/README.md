# Protocol Buffers

This directory contains [Protocol Buffer](https://developers.google.com/protocol-buffers) (protobuf)
definitions for third-party vault integrations.

## Structure

- `keeper/` — Protocol buffer definitions for Keeper vault import integration

## Generated Code

The `.proto` files in `keeper/` are compiled to Rust source code using
[`prost`](https://github.com/tokio-rs/prost). Generated Rust code is committed to the repository in
`src/importers/keeper/proto/` and should not be edited manually.

### Regenerating Proto Code

When you modify any `.proto` file in the `keeper/` directory, regenerate the corresponding Rust
code:

```bash
./support/build-keeper-proto.sh
```

This script uses `prost_build` to compile all `.proto` files and write the generated code to
`src/importers/keeper/proto/`. The generated files should then be reviewed and committed.

## Keeper Integration

The Keeper protocol buffer definitions are wire formats used by the Keeper vault client to serialize
and deserialize encrypted vault data. These are used by the Keeper importer to:

- Parse encrypted records and metadata from Keeper vault exports
- Decrypt and transform them into Bitwarden's standard vault models
- Handle authentication and encryption key derivation specific to Keeper's protocol

For implementation details and crypto considerations, see [CLAUDE.md](../CLAUDE.md) and the
[`keeper` module](../src/importers/keeper/).
