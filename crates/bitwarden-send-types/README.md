# Bitwarden Send Types

Contains the shared data types for Bitwarden Sends, such as [`SendType`].

This crate exists separately from `bitwarden-send` to break a dependency cycle: lower-level crates
(such as `bitwarden-policies`) must name these types without depending on the higher-level
`bitwarden-send` feature crate, which in turn will depend on those lower-level crates.
