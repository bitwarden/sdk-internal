# bitwarden-trust-log

Implements the Bitwarden **trust log**: a tamper-resistant, append-only chain of signed actions (key
additions and revocations, organization membership changes, device inventory, critical policy
changes) kept per actor — user, organization, or provider.

Each entry is a _link_ consisting of a small signed **outer link**, always served to any authorized
reader, and an **inner message** carrying the payload, whose readability is gated by the visibility
declared in the outer link. The chain of outer links gives completeness (no insertion, removal, or
reordering of an account's own history); a global transparency tree over every account's log head
gives freshness (no truncation or split view over time).

The full design — data structures, chain validation rules, key validity, the transparency tree, the
threat model, and the open questions — lives in [`trust-log.md`](./trust-log.md). That spec is a
**draft**: several load-bearing questions (epoch-head equivocation, inner-message confidentiality,
genesis-key trust) are unresolved.

## Status

Empty scaffold — nothing is implemented yet.

## Layering

This crate is a foundation crate: it must not depend on `bitwarden-core` or anything that does. The
`Client` surface for authoring and verifying logs will live in a separate feature crate once the
core types are in place.
