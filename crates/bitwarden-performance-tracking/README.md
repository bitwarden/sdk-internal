# bitwarden-performance-tracking

Performance tracing primitives. Wraps `performance.mark` / `performance.measure` so entries show up
as custom tracks in the Chrome DevTools performance panel, using the [performance extensibility
API][extensibility], and debug-logs the same data through `tracing`.

Everything here is a no-op on non-`wasm32` targets, so call sites need no `cfg`.

Entries are organized by three names:

```text
  ── Slow Crypto ─────────────────────────────  ◀ namespace (DevTools track group)
      Argon2id    ▉▉▉▉▉▉▉▉▉▉▉                  ◀ category  (DevTools track)
      PBKDF2      ▉▉▉▉▉                        ◀ one entry per `name`
  ── IPC ─────────────────────────────────────
      Messages    ▏▏▏▏   ▏▏  ▏▏▏▏   ▏▏
      Noise       ▉▉▉
```

## Usage

`start()` captures the start time and returns an event that writes its measurement when it is
dropped — so the entry is drawn even when the operation is left by a `?`, an early `return` or a
panic. Details known only once the work has run go on the event.

```rust
use bitwarden_performance_tracking::PerformanceEventDescriptor;

fn unlock() -> Result<Vec<u8>, ()> {
    let mut event = PerformanceEventDescriptor::new("Unlock", "UnlockClient", "unlock")
        .prop("method", "pin")
        .start();

    event.mark("session key unwrapped");

    let result = Err(());
    event.record_result(&result);

    result
}
```

For something that happens at a single point in time, use `log()`. It writes immediately with a
fixed nominal duration (a zero-length entry is not selectable in DevTools) and flags itself with the
`instant` property.

```rust
use bitwarden_performance_tracking::PerformanceEventDescriptor;

PerformanceEventDescriptor::new("IPC", "Messages", "Receive")
    .prop("bytes", 512)
    .log();
```

Unlike the flight recorder in `bitwarden-logging`, this is a live debugging aid rather than
telemetry: nothing is buffered, persisted or exported, and it is only visible to whoever has
DevTools open. **Never pass key material or vault data as a property** — the values are rendered
verbatim in the UI and captured in exported traces.

[extensibility]: https://developer.chrome.com/docs/devtools/performance/extension
