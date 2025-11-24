# bitwarden-state

Read [README.md](./README.md) for architecture overview and consult runnable code in
[examples/](./examples/) (usage demonstrations of the public API) and [tests/](./tests/)
(integration tests showing how components work together) for correct usage patterns.

## Critical Rules

**SDK-managed types require serialization**: Types must implement `Serialize + DeserializeOwned` to
use SDK-managed storage.

**Initialize database before access**: Call `initialize_database()` before accessing SDK-managed
repositories or `get_sdk_managed()` returns `DatabaseNotInitialized` error.
