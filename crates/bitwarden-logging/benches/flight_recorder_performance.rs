#![allow(missing_docs)]

use std::{hint::black_box, sync::Arc};

use bitwarden_logging::{
    CircularBuffer, FlightRecorderConfig, FlightRecorderEvent, FlightRecorderLayer,
};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use tracing_subscriber::{Registry, layer::SubscriberExt};

/// Benchmark 1: Event Construction
/// Measures FlightRecorderEvent::from_tracing_event() overhead.
/// Target: <500ns
fn bench_event_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_construction");
    group.throughput(Throughput::Elements(1));

    group.bench_function("from_tracing_event", |b| {
        // Setup: Create a layer to capture events for conversion testing
        let config = FlightRecorderConfig::default().with_max_events(1000);
        let layer = FlightRecorderLayer::new(config);
        let buffer = layer.buffer();

        let subscriber = Arc::new(Registry::default().with(layer));

        b.iter(|| {
            // Emit event and measure conversion overhead
            // The from_tracing_event happens inside on_event
            let sub = Arc::clone(&subscriber);
            tracing::subscriber::with_default(sub, || {
                tracing::info!("benchmark event");
            });

            // Clear the buffer for next iteration
            let _ = buffer.read();
        });
    });

    group.finish();
}

/// Benchmark 2: Buffer Operations
/// Measures CircularBuffer::push() cost.
/// Target: <100ns
fn bench_buffer_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("buffer_operations");
    group.throughput(Throughput::Elements(1));

    group.bench_function("circular_buffer_push", |b| {
        let buffer = CircularBuffer::new(1000);
        let event = FlightRecorderEvent {
            timestamp: 1234567890,
            level: "INFO".to_string(),
            target: "benchmark".to_string(),
            message: "test message".to_string(),
            fields: std::collections::HashMap::new(),
        };

        b.iter(|| black_box(buffer.push(event.clone())));
    });

    group.finish();
}

/// Benchmark 3: Full Layer Path
/// Measures full on_event() flow through the FlightRecorderLayer.
/// Target: <1μs
fn bench_full_layer_path(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_layer_path");
    group.throughput(Throughput::Elements(1));

    group.bench_function("on_event_complete", |b| {
        // Setup: Create subscriber with FlightRecorderLayer
        let config = FlightRecorderConfig::default().with_max_events(10000);
        let layer = FlightRecorderLayer::new(config);
        let buffer = layer.buffer();

        let subscriber = Arc::new(Registry::default().with(layer));

        b.iter(|| {
            // Emit a tracing event through the full layer path
            let sub = Arc::clone(&subscriber);
            tracing::subscriber::with_default(sub, || {
                black_box(tracing::info!("benchmark event with overhead measurement"));
            });

            // Clear the buffer for next iteration
            let _ = buffer.read();
        });
    });

    group.finish();
}

/// Benchmark 4: Buffer Sizes
/// Parametric comparison of buffer performance across different capacities.
fn bench_buffer_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("buffer_sizes");

    for size in [100, 500, 1000, 5000].iter() {
        group.bench_with_input(format!("capacity_{}", size), size, |b, &size| {
            let buffer = CircularBuffer::new(size);
            let event = FlightRecorderEvent {
                timestamp: 1234567890,
                level: "INFO".to_string(),
                target: "benchmark".to_string(),
                message: "test message".to_string(),
                fields: std::collections::HashMap::new(),
            };

            b.iter(|| black_box(buffer.push(event.clone())));
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_event_construction,
    bench_buffer_operations,
    bench_full_layer_path,
    bench_buffer_sizes
);
criterion_main!(benches);
