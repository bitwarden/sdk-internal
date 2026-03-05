#![allow(missing_docs)]

use std::{hint::black_box, sync::Arc};

use bitwarden_flight_recorder::{
    CircularBuffer, FlightRecorderConfig, FlightRecorderEvent, FlightRecorderLayer,
};
use tracing_subscriber::{Registry, layer::SubscriberExt};
use wasm_bindgen_test::{console_log, wasm_bindgen_test};

fn now_ms() -> f64 {
    js_sys::Date::now()
}

fn bench_loop(name: &str, iterations: u32, mut f: impl FnMut()) {
    // Warm up
    for _ in 0..100 {
        f();
    }

    let start = now_ms();
    for _ in 0..iterations {
        f();
    }
    let elapsed_ms = now_ms() - start;
    let per_iter_ns = (elapsed_ms * 1_000_000.0) / iterations as f64;

    let (value, unit) = if per_iter_ns < 1_000.0 {
        (per_iter_ns, "ns")
    } else if per_iter_ns < 1_000_000.0 {
        (per_iter_ns / 1_000.0, "µs")
    } else {
        (per_iter_ns / 1_000_000.0, "ms")
    };

    console_log!("{name}: {value:.2} {unit}/iter ({iterations} iterations)");
}

/// Benchmark 1: Event Construction
/// Measures FlightRecorderEvent::from_tracing_event() overhead.
/// Target: <500ns
fn bench_event_construction() {
    let config = FlightRecorderConfig::default().with_max_events(1000);
    let layer = FlightRecorderLayer::new(config);
    let buffer = layer.buffer();
    let subscriber = Arc::new(Registry::default().with(layer));

    bench_loop("event_construction", 10_000, || {
        let sub = Arc::clone(&subscriber);
        tracing::subscriber::with_default(sub, || {
            tracing::info!("benchmark event");
        });
        let _ = buffer.read();
    });
}

/// Benchmark 2: Buffer Operations
/// Measures CircularBuffer::push() cost.
/// Target: <100ns
fn bench_buffer_operations() {
    let buffer = CircularBuffer::new(1000);
    let event = FlightRecorderEvent {
        timestamp: 1234567890,
        level: "INFO".to_string(),
        target: "benchmark".to_string(),
        message: "test message".to_string(),
        fields: std::collections::HashMap::new(),
    };

    bench_loop("circular_buffer_push", 100_000, || {
        black_box(buffer.push(event.clone()));
    });
}

/// Benchmark 3: Full Layer Path
/// Measures full on_event() flow through the FlightRecorderLayer.
/// Target: <1µs
fn bench_full_layer_path() {
    let config = FlightRecorderConfig::default().with_max_events(10000);
    let layer = FlightRecorderLayer::new(config);
    let buffer = layer.buffer();
    let subscriber = Arc::new(Registry::default().with(layer));

    bench_loop("full_layer_path", 10_000, || {
        let sub = Arc::clone(&subscriber);
        tracing::subscriber::with_default(sub, || {
            tracing::info!("benchmark event with overhead measurement");
        });
        let _ = buffer.read();
    });
}

/// Benchmark 4: Buffer Sizes
/// Parametric comparison of buffer performance across different capacities.
fn bench_buffer_sizes() {
    for size in [100, 500, 1000, 5000] {
        let buffer = CircularBuffer::new(size);
        let event = FlightRecorderEvent {
            timestamp: 1234567890,
            level: "INFO".to_string(),
            target: "benchmark".to_string(),
            message: "test message".to_string(),
            fields: std::collections::HashMap::new(),
        };

        bench_loop(&format!("buffer_capacity_{size}"), 100_000, || {
            black_box(buffer.push(event.clone()));
        });
    }
}

#[wasm_bindgen_test]
fn bench() {
    bench_event_construction();
    bench_buffer_operations();
    bench_full_layer_path();
    bench_buffer_sizes();
}
