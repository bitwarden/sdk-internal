# Bitwarden Logging

Flight Recorder infrastructure for capturing and exporting diagnostic logs.

Internal crate for the bitwarden crate. Do not use.

## Working With FlightRecorder

The Flight Recorder captures tracing events into a global circular buffer so they can be exported
for diagnostics without requiring the caller to hold a direct reference to the buffer. Once IPC
forwarding is enabled (see [Aggregation over IPC](#aggregation-over-ipc)), events go to the
collector instead and the local buffer keeps only events from the IPC stack.

### Initialization

Call `init_flight_recorder` during SDK startup and add the returned layer to your tracing
subscriber:

```rust
use bitwarden_logging::{init_flight_recorder, FlightRecorderConfig};
use tracing_subscriber::{layer::SubscriberExt as _, util::SubscriberInitExt as _};

let flight_recorder_layer = init_flight_recorder(FlightRecorderConfig::default());

tracing_subscriber::registry()
    .with(flight_recorder_layer)
    .init();
```

The default configuration retains 1 000 events at `DEBUG` level. Use `FlightRecorderConfig::new` for
custom settings.

### Reading events

Once initialized, events can be read from anywhere in the process:

```rust
use bitwarden_logging::{read_flight_recorder, flight_recorder_count};

let count = flight_recorder_count();
let events = read_flight_recorder();
```

Both functions return safe defaults (`0` / empty `Vec`) if the recorder has not been initialized.
They read only this context's buffer. In a forwarder, use `ipc::read_flight_recorder_aggregated` to
include the collector's events.

### WASM usage

In `bitwarden-wasm-internal`, the recorder is automatically initialized by `init_sdk()`. TypeScript
consumers access it through `FlightRecorderClient`:

```typescript
import { FlightRecorderClient } from "@aspect/bitwarden-wasm-internal";

const recorder = new FlightRecorderClient();
const count = recorder.count();
const events = await recorder.read();
```

Each `FlightRecorderEvent` contains `timestamp`, `level`, `target`, `message`, `fields`, and
`process`.

### Aggregation over IPC

The `ipc` cargo feature lets clients with several contexts collect their events in one context over
`bitwarden-ipc`. One context is the collector (browser background, desktop main) and the others are
forwarders that send their events to it. Forwarders keep events from the IPC stack itself locally.
The collector labels each event's `process` with the context it came from, and only accepts
messages from its own client's forwarders.

The WASM bindings expose this as `enableFlightRecorderCollection` and
`enableFlightRecorderForwarding`. In a forwarder, `recorder.read()` returns the collector's events
followed by its own, falling back to its own events if the collector does not answer.
