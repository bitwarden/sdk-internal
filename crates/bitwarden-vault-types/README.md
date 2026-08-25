# Bitwarden Vault Types

Contains the shared data types for the Bitwarden vault, such as [`UriMatchType`].

This crate exists separately from `bitwarden-vault` to break a dependency cycle: lower-level crates
(such as `bitwarden-policies`) must name these types without depending on the higher-level
`bitwarden-vault` feature crate, which in turn will depend on those lower-level crates.
