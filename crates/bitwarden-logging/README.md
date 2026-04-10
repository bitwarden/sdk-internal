# Bitwarden Logging

Flight Recorder infrastructure for capturing and exporting diagnostic logs.

Internal crate for the bitwarden crate. Do not use.

## Working With FlightRecorder

The Flight Recorder captures tracing events into a global circular buffer so they can be exported
for diagnostics without requiring the caller to hold a direct reference to the buffer.

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

### WASM usage

In `bitwarden-wasm-internal`, the recorder is automatically initialized by `init_sdk()`. TypeScript
consumers access it through `FlightRecorderClient`:

```typescript
import { FlightRecorderClient } from "@aspect/bitwarden-wasm-internal";

const recorder = new FlightRecorderClient();
const count = recorder.count();
const events = recorder.read();
```

Each `FlightRecorderEvent` contains `timestamp`, `level`, `target`, `message`, and `fields`.
