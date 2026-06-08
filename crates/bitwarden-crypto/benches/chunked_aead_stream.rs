#![allow(missing_docs)]

use std::hint::black_box;

use bitwarden_crypto::SymmetricCryptoKey;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

/// Size of each `update` write fed to the streaming ciphers.
const INPUT_CHUNK: usize = 64 * 1024;

/// Plaintext sizes (bytes) exercised by the encrypt/decrypt throughput benchmarks.
const SIZES: [usize; 3] = [64 * 1024, 1024 * 1024, 16 * 1024 * 1024];

fn algorithms() -> [(&'static str, BenchAeadAlgorithm); 2] {
    [
        ("aes256gcm", BenchAeadAlgorithm::Aes256Gcm),
        ("chacha20poly1305", BenchAeadAlgorithm::ChaCha20Poly1305),
    ]
}

fn bench_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunked_aead_encrypt");
    for size in SIZES {
        let plaintext = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        for (name, alg) in algorithms() {
            let key = SymmetricCryptoKey::make(alg);
            group.bench_with_input(BenchmarkId::new(name, size), &plaintext, |b, pt| {
                b.iter(|| black_box(bench_support::encrypt(&key, black_box(pt), INPUT_CHUNK)))
            });
        }
    }
    group.finish();
}

fn bench_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunked_aead_decrypt");
    for size in SIZES {
        let plaintext = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        for (name, alg) in algorithms() {
            let key = SymmetricCryptoKey::make(alg);
            let wire = bench_support::encrypt(&key, &plaintext, INPUT_CHUNK);
            group.bench_with_input(BenchmarkId::new(name, size), &wire, |b, w| {
                b.iter(|| black_box(bench_support::decrypt(&key, black_box(w), INPUT_CHUNK)))
            });
        }
    }
    group.finish();
}

fn bench_random_access(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("tokio runtime");

    // A few chunks worth of plaintext (the default chunk is 64 KiB).
    let plaintext = vec![0u8; 4 * 64 * 1024 + 1234];
    // (a) a small range within the first chunk, (b) a range spanning a chunk boundary.
    let ranges = [
        ("within_chunk", 100usize..(100 + 32 * 1024)),
        ("across_chunk", (64 * 1024 - 4096)..(64 * 1024 + 4096)),
    ];

    let mut group = c.benchmark_group("chunked_aead_random_access");
    for (range_name, range) in ranges {
        group.throughput(Throughput::Bytes((range.end - range.start) as u64));
        for (name, alg) in algorithms() {
            let key = SymmetricCryptoKey::make(alg);
            let wire = bench_support::encrypt(&key, &plaintext, INPUT_CHUNK);
            group.bench_with_input(BenchmarkId::new(name, range_name), &wire, |b, w| {
                b.iter(|| {
                    black_box(rt.block_on(bench_support::decrypt_range(
                        &key,
                        black_box(w),
                        range.clone(),
                    )))
                })
            });
        }
    }
    group.finish();
}

criterion_group!(benches, bench_encrypt, bench_decrypt, bench_random_access);
criterion_main!(benches);
