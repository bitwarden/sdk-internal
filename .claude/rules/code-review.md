---
paths:
  - "crates/**/*.rs"
  - "bitwarden_license/**/*.rs"
---

# Code review rules

Enforceable review rules distilled from Bitwarden SDK power-user PR feedback, each tagged with its
severity. Topic-specific rules also live in the sibling rules files (`crypto.md`,
`rust-conventions.md`, `bindings.md`); these complement, not replace, them.

1. `[CRITICAL]` Never use `Vec<u8>` / `String` to carry keys or crypto material; use typed newtypes
   (e.g. `SymmetricKey`) so key material cannot be confused with ordinary bytes. (See `crypto.md`
   for the key-reference / hazmat rules this builds on.)
2. `[IMPORTANT]` New functionality lives on a `Client` struct via extension traits
   (`client.vault() -> VaultClient`), not as standalone statics or free functions.
3. `[CRITICAL]` New crypto operations and FFI exports require pinned test vectors — JSON vectors
   pinned in code; see the `create-testvectors` skill.
4. `[CRITICAL]` Never re-expose low-level / hazmat crypto through a feature crate's public API (the
   crypto crates already must not expose it; this rule covers feature crates re-exporting it
   downstream — see `crypto.md`).
5. `[IMPORTANT]` All public types need doc comments; do NOT suppress `missing_docs` crate-wide to
   silence the warning.
6. `[IMPORTANT]` Use restrictive visibility by default (`pub(crate)` / `pub(super)`); a bare `pub`
   must be justified by a real cross-crate consumer.
7. `[CRITICAL]` An IV / nonce must never be passed in from outside; generate it internally at the
   point of encryption.
8. `[DEBT]` No untracked `TODO`s — every `TODO` must link a Jira ticket.
9. `[SUGGESTED]` Public docs describe usage and interface only, not internals; avoid
   over-documentation that restates the implementation.
10. `[IMPORTANT]` Use Cargo weak dependencies (`?`) for optional / licensed crates, so an optional
    feature does not implicitly pull a crate across the OSS boundary.
