use bitwarden_crypto::chacha20::{
    decrypt_xchacha20_poly1305_blake3_ctx, encrypt_xchacha20_poly1305_blake3_ctx,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

pub fn criterion_benchmark(c: &mut Criterion) {
    let key = [0u8; 32];
    let plaintext_secret_data = vec![0u8; 1024];
    let plaintext_secret_data = plaintext_secret_data.as_slice();
    let authenticated_data = vec![0u8; 256];
    let authenticated_data = authenticated_data.as_slice();

    c.bench_function("encrypt_xchacha20_poly1305_blake3_ctx", |b| {
        b.iter(|| {
            encrypt_xchacha20_poly1305_blake3_ctx(
                black_box(&key),
                black_box(plaintext_secret_data),
                black_box(authenticated_data),
            )
        })
    });

    let encrypted =
        encrypt_xchacha20_poly1305_blake3_ctx(&key, plaintext_secret_data, authenticated_data)
            .unwrap();

    c.bench_function("encrypt_xchacha20_poly1305_blake3_ctx", |b| {
        b.iter(|| decrypt_xchacha20_poly1305_blake3_ctx(black_box(&key), black_box(&encrypted)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
