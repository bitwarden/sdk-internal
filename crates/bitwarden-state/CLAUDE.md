# bitwarden-state

Read any available documentation: [README.md](./README.md) for architecture,
[examples/](./examples/) for usage patterns, and [tests/](./tests/) for integration tests.

## Critical Rules

**SDK-managed types require serialization**: Types must implement `Serialize + DeserializeOwned` to
use SDK-managed storage.

**Initialize database before access**: Call `initialize_database()` before accessing SDK-managed
repositories or `get_sdk_managed()` returns `DatabaseNotInitialized` error.
