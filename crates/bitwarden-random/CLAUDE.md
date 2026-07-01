# bitwarden-random

Read any available documentation: [README.md](./README.md) for architecture,
[examples/](./examples/) for usage patterns, and [tests/](./tests/) for integration tests.

The single random-number source for the SDK. Wraps the OS CRNG behind [`SdkRngImpl`] and the `rng()`
constructor, and exposes cross-platform generation through [`SdkRandomNumberClient`].

## Critical Rules

**Use `rng()`, never `rand::rng()` directly**: All SDK crates draw randomness through
`bitwarden_random::rng()` so a single, auditable CRNG (and the test seeding hook) backs every
generator. Do not call `rand::rng()`, `rand::rngs::OsRng`, or `SysRng` from other crates.

**Only OS entropy in production**: The default `SdkRngImpl` is OS-backed. The seeded stream exists
solely for reproducible tests.

**`dangerous-seeded-rng-for-testing` is test-only**: It installs a deterministic ChaCha8 stream on
the current thread. NEVER enable it in a production code path, since it makes all randomness
predictable.

**Implements standard traits**: The crate implements standard traits for the `SdkRngImpl`. It
can be dropped in and used for all external libraries that accept an RNG.