//! Performance benchmarks for the FlightRecorder subsystem.
//!
//! These benchmarks measure the overhead of the FlightRecorder tracing layer and circular buffer,
//! ensuring they stay within acceptable limits for production use.
//!
//! ## Performance targets
//!
//! | Benchmark     | Target                                      |
//! |---------------|---------------------------------------------|
//! | Event capture | <500ns per event (simple messages)          |
//! | Buffer push   | <100ns per push, <10% variance across sizes |
//! | Buffer read   | <100ns per event cloned                     |
//!
//! ## Running
//!
//! ```sh
//! # Run all benchmarks
//! cargo bench -p bitwarden-logging
//!
//! # Run a specific group
//! cargo bench -p bitwarden-logging -- event_capture
//! ```
//!
//! After running, Criterion generates HTML reports in `target/criterion/`. Open
//! `target/criterion/report/index.html` to view detailed graphs and statistical analysis.

#![allow(missing_docs, clippy::unwrap_used)]

use std::{collections::HashMap, hint::black_box, num::NonZeroUsize};

use bitwarden_logging::{
    CircularBuffer, FlightRecorderConfig, FlightRecorderEvent, FlightRecorderLayer,
};
use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use tracing_subscriber::layer::SubscriberExt;

/// Create a representative event for buffer benchmarks.
fn test_event() -> FlightRecorderEvent {
    FlightRecorderEvent {
        timestamp: 1234567890,
        level: "INFO".to_string(),
        target: "bench::module".to_string(),
        message: "benchmark event".to_string(),
        fields: HashMap::new(),
    }
}

/// Benchmarks the end-to-end cost of a tracing event being captured by FlightRecorderLayer.
/// This is the hot path in production: every `tracing::info!()` (or similar) call passes through
/// `on_event`, which constructs a `FlightRecorderEvent` (timestamp, string allocations, field
/// visitor) and pushes it into the circular buffer.
///
/// Target: <500ns per event for simple messages.
fn bench_event_capture(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_capture");
    group.throughput(Throughput::Elements(1));

    let config =
        FlightRecorderConfig::new(NonZeroUsize::new(10_000).unwrap(), tracing::Level::DEBUG);
    let layer = FlightRecorderLayer::new(config);
    let subscriber = tracing_subscriber::registry().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    // Simple message with no structured fields — the cheapest capture path.
    group.bench_function("simple_message", |b| {
        b.iter(|| {
            tracing::info!(target: "bench::module", "benchmark event");
        });
    });

    // Message with structured fields — exercises the MessageVisitor and HashMap
    // allocation. Most real-world usage includes at least a few fields.
    group.bench_function("with_structured_fields", |b| {
        b.iter(|| {
            tracing::info!(
                target: "bench::module",
                user_id = "abc-123",
                action = "login",
                success = true,
                "structured event"
            );
        });
    });

    // Event below the configured level threshold — tests the fast-reject path.
    // Should be near-zero cost since the layer returns immediately.
    group.bench_function("filtered_by_level", |b| {
        b.iter(|| {
            tracing::trace!(target: "bench::module", "filtered out by level");
        });
    });

    group.finish();
}

/// Benchmarks CircularBuffer::push across different buffer capacities.
/// Push involves a mutex lock, and when at capacity, a VecDeque::pop_front + push_back.
/// Both operations are O(1) amortized, so performance should be consistent regardless
/// of buffer size.
///
/// Targets: <100ns per push, <10% variance across capacities.
fn bench_buffer_push(c: &mut Criterion) {
    let mut group = c.benchmark_group("buffer_push");
    group.throughput(Throughput::Elements(1));

    let event = test_event();

    for size in [1_000, 10_000, 100_000] {
        // Buffer is full — every push evicts the oldest item via pop_front.
        group.bench_with_input(BenchmarkId::new("at_capacity", size), &size, |b, &size| {
            let buffer = CircularBuffer::new(NonZeroUsize::new(size).unwrap());
            for _ in 0..size {
                buffer.push(event.clone());
            }
            b.iter(|| buffer.push(black_box(event.clone())));
        });

        // Buffer is empty — push appends without eviction.
        // Uses iter_batched to get a fresh buffer per iteration, otherwise
        // the buffer fills up across Criterion's millions of iterations.
        group.bench_with_input(
            BenchmarkId::new("under_capacity", size),
            &size,
            |b, &size| {
                b.iter_batched(
                    || CircularBuffer::new(NonZeroUsize::new(size).unwrap()),
                    |buffer| buffer.push(black_box(event.clone())),
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

/// Benchmarks CircularBuffer::read, which clones all buffered events into a Vec.
/// This is the export path used when the flight recorder contents are retrieved
/// (e.g. for crash reports or diagnostics). Cost scales linearly with buffer size.
///
/// Target: <100ns per event cloned.
fn bench_buffer_read(c: &mut Criterion) {
    let mut group = c.benchmark_group("buffer_read");
    let event = test_event();

    for size in [1_000, 10_000, 100_000] {
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::new("read_full", size), &size, |b, &size| {
            let buffer = CircularBuffer::new(NonZeroUsize::new(size).unwrap());
            for _ in 0..size {
                buffer.push(event.clone());
            }
            b.iter(|| black_box(buffer.read()));
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_event_capture,
    bench_buffer_push,
    bench_buffer_read
);
criterion_main!(benches);
