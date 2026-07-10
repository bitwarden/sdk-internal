# Commercial (Bitwarden-licensed) crates

Every crate in this directory is commercial and must **never** ship in a non-commercial build. They
are pulled in exclusively through a consumer's `bitwarden-license` feature, and consumers must
reference them weakly in other feature lists (`bitwarden-commercial-vault?/wasm`, never
`bitwarden-commercial-vault/wasm`) so enabling `wasm`/`uniffi` doesn't force them in.

## Compile-time guard: `bitwarden-commercial-marker`

Every crate here (except `bitwarden-commercial-marker` itself) must depend on the marker and invoke
its macro once in `lib.rs`:

```toml
# Cargo.toml
bitwarden-commercial-marker = { workspace = true }
```

```rust
// lib.rs
bitwarden_commercial_marker::commercial_crate!();
```

The macro expands to nothing normally, but to a `compile_error!` when the crate is built with
`--cfg bitwarden_ensure_non_commercial`. CI builds the non-commercial artifacts with
`RUSTFLAGS="--cfg bitwarden_ensure_non_commercial"`, so any commercial crate that leaked in fails
the build.

## Code review checklist

- Every crate directly under `bitwarden_license/` (except the marker) depends on
  `bitwarden-commercial-marker` **and** calls `bitwarden_commercial_marker::commercial_crate!();` in
  its `lib.rs`. A new crate added here without both is a blocking finding. (The unused-dependency
  lint catches a missing macro call, but not a missing dependency, so check the dependency too.)
- Consumers reference these crates weakly (`?/`) in every feature except `bitwarden-license`.
