---
applyTo: "**/Cargo.toml"
---

# Project coding standards for Cargo.toml

## Workspace Dependency Management

### External Dependencies

When adding a new dependency to a `Cargo.toml`, you **MUST** scan all existing `Cargo.toml` files in
the repository to ensure it is not already defined in another crate. If it is, you should add it to
the workspace dependencies and remove it from the individual crate.

```toml
# ✅ DO: Define in root workspace
[workspace.dependencies]
serde = { version = ">=1.0, <2.0", features = ["derive"] }
tokio = { version = "1.36.0", features = ["macros"] }
```

```toml
# ❌ DON'T: Define different versions in individual crates
[dependencies]
serde = "1.0.150"  # Different version than workspace
```

### Internal Dependencies

All internal crates must be listed in workspace dependencies with exact version matching:

```toml
[workspace.dependencies]
bitwarden-core = { path = "crates/bitwarden-core", version = "=1.0.0" }
bitwarden-crypto = { path = "crates/bitwarden-crypto", version = "=1.0.0" }
```

### Using Workspace Dependencies

In individual crate `Cargo.toml` files, always reference workspace dependencies:

```toml
[dependencies]
# ✅ DO: Use workspace dependencies
serde = { workspace = true }
bitwarden-crypto = { workspace = true }

# ✅ OK: Add features to workspace dependency
serde = { workspace = true, features = ["derive"] }

# ❌ DON'T: Override workspace version
serde = "1.0.200"
```

## Package Metadata

### Required Workspace Inheritance

All crates must inherit common metadata from workspace:

```toml
[package]
name = "bitwarden-example"
description = "Brief description of the crate's purpose"

# Required workspace inheritance
version.workspace = true
authors.workspace = true
edition.workspace = true
rust-version.workspace = true
readme.workspace = true
homepage.workspace = true
repository.workspace = true
license-file.workspace = true
keywords.workspace = true
```

## Feature Flags

### Standard Feature Patterns

Follow established feature flag patterns:

- `uniffi` - Mobile bindings via UniFFI
- `wasm` - WebAssembly support

### Feature Flag Dependencies

Use conditional dependencies with feature flags:

```toml
[features]
uniffi = ["bitwarden-crypto/uniffi", "dep:uniffi"]
wasm = ["dep:wasm-bindgen", "dep:tsify"]

[dependencies]
# Conditional dependencies
uniffi = { workspace = true, optional = true }
wasm-bindgen = { workspace = true, optional = true }
```

## Version Constraints

Use compatible version ranges for external dependencies:

```toml
# ✅ DO: Allow patch updates
serde = ">=1.0, <2.0"
chrono = ">=0.4.26, <0.5"

# ❌ DON'T: Pin to exact external versions unless necessary
serde = "=1.0.150"
```

## Special Considerations

### Patches

Document any `[patch.crates-io]` entries with reasoning:

```toml
# Temporary fix for WASM compatibility issue
# TODO: Remove when upstream releases fix
[patch.crates-io]
pkcs5 = { git = "https://github.com/bitwarden/rustcrypto-formats.git", rev = "abc123" }
```

### Profile Optimizations

Development profiles are configured at workspace level - do not override in individual crates unless
absolutely necessary.
