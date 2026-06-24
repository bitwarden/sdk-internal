---
name: create-testvectors
description:
  Record a serialized/encrypted format as a permanent test vector. Use when adding a type whose
  serialization format must stay backward-compatible (envelopes, COSE blobs, encrypted/wire
  formats), or when the user asks to "create a test vector", "record a serialized format", or "lock
  in the wire format". Generates output with a temporary ignored test, then pins it in a permanent
  deserialization unit test.
allowed-tools: Bash(cargo test:*), Bash(npm run lint)
---

# Create a serialization test vector

Backward compatibility of serialized data is critical in this SDK: existing encrypted/serialized
data must keep deserializing across versions. A **test vector** locks a known-good serialized blob
into a permanent unit test that fails if the format ever silently breaks.

The workflow has two halves: a throwaway generator test that prints the blob, and a permanent test
that parses a hardcoded copy of that blob and asserts it decodes to the expected value.

## Reference implementations

Read these before writing a new one; copy whichever style fits:

- `crates/bitwarden-crypto/src/safe/data_envelope.rs` — base64 `&str` constants (preferred for
  larger/COSE blobs). See `generate_test_vectors` (the ignored generator) and
  `test_data_envelope_test_vector` (the permanent check).
- `crates/bitwarden-crypto/src/safe/password_protected_key_envelope.rs` — `&[u8]` byte-array
  constants. See `TESTVECTOR_*` consts and `test_testvector_cosekey` / `test_testvector_legacykey`.

## Steps

### 1. Pick the encoding for the constant

- **Base64 `&str`** (preferred) when the type implements `From<T> for String` / `FromStr` (or serde
  to a B64 string), e.g. `DataEnvelope`. Compact in source.
- **`&[u8]` byte array** when the type only round-trips through raw bytes (`From<&T> for Vec<u8>` /
  `TryFrom<&Vec<u8>>`), e.g. `PasswordProtectedKeyEnvelope`.

Use a **fixed, deterministic** input value and a **stable test namespace** (e.g. `ExampleNamespace`)
so the permanent test is self-contained.

### 2. Write a temporary generator test

Add to the crate's `#[cfg(test)] mod tests`. Mark it `#[ignore]` so it never runs in CI — its only
job is to print constants you paste back into the source.

```rust
#[test]
#[ignore = "Generates test vectors; run manually"]
fn generate_test_vectors() {
    // Construct with a fixed input + stable namespace.
    let data: TestData = TestDataV1 { field: 123 }.into();
    let (envelope, cek) =
        DataEnvelope::seal_ref(&data, DataEnvelopeNamespace::ExampleNamespace).unwrap();

    // Round-trip once here to confirm the generated vector is itself valid.
    let unsealed: TestData = envelope
        .unseal_ref(DataEnvelopeNamespace::ExampleNamespace, &cek)
        .unwrap();
    assert_eq!(unsealed, data);

    // Print constants in the exact form you'll paste back.
    println!(
        "const TEST_VECTOR_CEK: &str = \"{}\";",
        B64::from(SymmetricCryptoKey::XChaCha20Poly1305Key(cek).to_encoded())
    );
    println!("const TEST_VECTOR_ENVELOPE: &str = \"{}\";", String::from(envelope));
}
```

For the byte-array style, print with `println!("{:?}", some_bytes)` and paste the array.

### 3. Run it and capture the output

```
cargo test -p <crate> <module>::tests::generate_test_vectors -- --ignored --nocapture
```

Copy the printed `const` lines verbatim.

### 4. Add the permanent test vector + check

Paste the captured constants as module-level `const`s, then write a permanent (non-ignored) test
that reconstructs from the constant and asserts the decoded value equals the known input. This is
what guards against format breakage.

```rust
const TEST_VECTOR_CEK: &str = "pQEEAlB5RTKA0xXdA7C4iQE4QfVU...";
const TEST_VECTOR_ENVELOPE: &str = "g1hLpQE6AAERbwN4I2FwcGxpY2F0...";

#[test]
fn test_data_envelope_test_vector() {
    let cek = SymmetricCryptoKey::try_from(B64::try_from(TEST_VECTOR_CEK).unwrap()).unwrap();
    let SymmetricCryptoKey::XChaCha20Poly1305Key(ref cek) = cek else {
        panic!("Invalid CEK type");
    };

    let envelope: DataEnvelope = TEST_VECTOR_ENVELOPE.parse().unwrap();
    let unsealed: TestData = envelope
        .unseal_ref(DataEnvelopeNamespace::ExampleNamespace, cek)
        .unwrap();
    assert_eq!(unsealed, TestDataV1 { field: 123 }.into());
}
```

### 5. Delete the generator and verify

- Remove the temporary `#[ignore]` generator test (the reference files keep theirs, which is also
  acceptable — keep it only if it's genuinely useful to regenerate later).
- Run the permanent test and lint:

```
cargo test -p <crate> <module>::tests::test_..._test_vector
npm run lint
```

## Rules

- **Never regenerate an existing committed vector to make a failing test pass.** A vector that stops
  decoding means a real backward-compatibility break — fix the code, not the vector.
- The permanent test must assert the **decoded value**, not just that parsing succeeds.
- Keep inputs deterministic; do not seal with random values you don't print.
- Don't log/commit real keys or vault data — use test keys and test namespaces only.
