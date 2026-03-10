#![allow(missing_docs)]

use std::{hint::black_box, sync::Arc};

use bitwarden_logging::{
    CircularBuffer, FlightRecorderConfig, FlightRecorderEvent, FlightRecorderLayer,
};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use tracing_subscriber::{Registry, layer::SubscriberExt};

/// Benchmark 1: Event Construction Overhead
/// Measures the overhead of FlightRecorderLayer by comparing baseline tracing
/// overhead vs tracing + FlightRecorderLayer overhead.
/// Target: FlightRecorderLayer adds <500ns
fn bench_event_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_construction");
    group.throughput(Throughput::Elements(1));

    // Baseline: measure tracing overhead without FlightRecorderLayer
    group.bench_function("baseline_tracing_overhead", |b| {
        // No-op layer that does nothing in on_event
        #[derive(Clone)]
        struct NoOpLayer;
        impl<S> tracing_subscriber::Layer<S> for NoOpLayer
        where
            S: tracing::Subscriber,
        {
            fn on_event(
                &self,
                _event: &tracing::Event<'_>,
                _ctx: tracing_subscriber::layer::Context<'_, S>,
            ) {
            }
        }

        let subscriber = Arc::new(Registry::default().with(NoOpLayer));

        b.iter(|| {
            // Only the logging call is measured
            let sub = Arc::clone(&subscriber);
            tracing::subscriber::with_default(sub, || {
                black_box(tracing::info!("benchmark event"));
            });
        });
    });

    // Full measurement: tracing + FlightRecorderLayer
    group.bench_function("with_flight_recorder_layer", |b| {
        let config = FlightRecorderConfig::default().with_max_events(10000);
        let layer = FlightRecorderLayer::new(config);
        let buffer = layer.buffer();

        let subscriber = Arc::new(Registry::default().with(layer));

        b.iter(|| {
            // Only the logging call is measured
            let sub = Arc::clone(&subscriber);
            tracing::subscriber::with_default(sub, || {
                black_box(tracing::info!("benchmark event"));
            });
        });

        // Clean up
        let _ = buffer.read();
    });

    group.finish();
}

/// Benchmark 2: Buffer Operations
/// Measures CircularBuffer::push() cost in isolation.
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

/// Benchmark 3: Full Layer Path (Minimal Overhead)
/// Measures complete logging overhead with subscriber setup outside measurement.
/// This is the closest to production usage pattern.
/// Target: <1μs per log call
fn bench_full_layer_path(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_layer_path");
    group.throughput(Throughput::Elements(1));

    group.bench_function("production_logging_overhead", |b| {
        let config = FlightRecorderConfig::default().with_max_events(10000);
        let layer = FlightRecorderLayer::new(config);
        let buffer = layer.buffer();

        let subscriber = Arc::new(Registry::default().with(layer));

        b.iter(|| {
            // Measure just the logging call
            let sub = Arc::clone(&subscriber);
            tracing::subscriber::with_default(sub, || {
                black_box(tracing::info!(
                    event_type = "benchmark",
                    iteration = 1,
                    "benchmark event with structured fields"
                ));
            });
        });

        let _ = buffer.read();
    });

    group.finish();
}

/// Benchmark 4: Layer Overhead Components
/// Break down where time is spent in the layer
fn bench_layer_components(c: &mut Criterion) {
    let mut group = c.benchmark_group("layer_components");
    group.throughput(Throughput::Elements(1));

    // Measure just the timestamp acquisition
    group.bench_function("timestamp_acquisition", |b| {
        b.iter(|| {
            black_box(chrono::Utc::now().timestamp_millis());
        });
    });

    // Measure simple event (no fields)
    group.bench_function("simple_event_no_fields", |b| {
        let config = FlightRecorderConfig::default().with_max_events(10000);
        let layer = FlightRecorderLayer::new(config);
        let buffer = layer.buffer();

        let subscriber = Arc::new(Registry::default().with(layer));

        b.iter(|| {
            let sub = Arc::clone(&subscriber);
            tracing::subscriber::with_default(sub, || {
                black_box(tracing::info!("simple message"));
            });
        });

        let _ = buffer.read();
    });

    // Measure event with structured fields
    group.bench_function("event_with_fields", |b| {
        let config = FlightRecorderConfig::default().with_max_events(10000);
        let layer = FlightRecorderLayer::new(config);
        let buffer = layer.buffer();

        let subscriber = Arc::new(Registry::default().with(layer));

        b.iter(|| {
            let sub = Arc::clone(&subscriber);
            tracing::subscriber::with_default(sub, || {
                black_box(tracing::info!(
                    user_id = "12345",
                    action = "login",
                    success = true,
                    "user logged in"
                ));
            });
        });

        let _ = buffer.read();
    });

    group.finish();
}

/// Benchmark 5: Buffer Sizes
/// Parametric comparison of buffer performance across different capacities.
/// Validates O(1) complexity claim.
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
    bench_layer_components,
    bench_buffer_sizes
);
criterion_main!(benches);
