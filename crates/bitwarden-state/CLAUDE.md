# bitwarden-state

Read any available documentation: [README.md](./README.md) for architecture,
[examples/](./examples/) for usage patterns, and [tests/](./tests/) for integration tests.

## Critical Rules

**SDK-managed types require serialization**: Types must implement `Serialize + DeserializeOwned` to
use SDK-managed storage.

**Choose the right constructor**: Use `StateRegistry::new_with_memory_db()` for in-memory storage
(sync, suitable for tests or apps that use only client-managed storage). Use
`StateRegistry::new_with_db(configuration, migrations)` (async) for persistent storage — pass all
migrations at construction time, not after the fact.

**Register client-managed persisted values before building handles**: `PersistedValue<K>` captures
its backend when it is built, so a backend registered with `register_client_managed_value` after
that is not seen by existing handles or by feature clients built from them.
