# Implementation Guidance

Rules for implementing [hibp-bulk-proto.md](hibp-bulk-proto.md) and
[enclave-comms-proto.md](enclave-comms-proto.md).

## Oblivious lookups

### Threat

SEV-SNP encrypts memory but does not hide _where_ the enclave reads. The host controls the
hypervisor and observes:

| Channel                                  | Granularity     | Example attacks                                |
| ---------------------------------------- | --------------- | ---------------------------------------------- |
| Page faults (host unmaps / remaps pages) | 4 KiB page      | Controlled-channel attacks                     |
| Single-stepping via timer interrupts     | Instruction     | SEV-Step                                       |
| Shared caches                            | 64 B cache line | Prime+Probe                                    |
| Memory ciphertext                        | 16 B block      | CipherLeaks (ciphertext changes reveal writes) |
| Timing                                   | Request latency | Early exit, variable work per hash             |

The HIBP set is public. Knowing _which_ entry the enclave touched is knowing the queried hash:

```
naive hash table  →  slot address  →  public entry  →  password hash
binary search     →  probe path    →  narrows to 1 entry
bucket scan       →  bucket address →  5-nibble prefix (= range API leak)
ORAM / full scan  →  random path    →  nothing
```

### Options

| Approach                          | Host learns                      | Cost per query        |
| --------------------------------- | -------------------------------- | --------------------- |
| Hash table / binary search        | Full hash                        | O(1) / O(log M)       |
| Scan whole 5-nibble bucket        | 20-bit prefix, same as range API | ~2300 rows            |
| Path ORAM, block = padded bucket  | Nothing                          | ~1.5 MiB read + write |
| Oblivious linear scan of full set | Nothing                          | Full set per batch    |

Path ORAM layout: 2²⁰ blocks (one per prefix, padded to a fixed row count), tree depth ~20, bucket
size Z = 4, position map 4 MiB scanned in full per access. Storage ~2–4× the set. The set is public,
so the ORAM is built non-obliviously at each refresh; only lookups must be oblivious.

### Rules

- No branch, loop bound, or memory index depends on a hash or a result.
- Compare with constant-time primitives (Rust `subtle`, `cmov`), never `==` with early exit.
- Scan the full bucket, stash, and position map on every access.
- Process all `n` hashes with identical work; build the bitmap with bitwise ops.
- Pad every bucket to the same row count.
- Never log, trace, or allocate based on hashes or results.
- Use a validated DRBG for ORAM leaf remapping.
- Check compiler output: optimizers can turn `cmov` back into branches.

### Testing

- Timing: dudect-style statistical tests across hit / miss / prefix.
- Access patterns: record memory traces (e.g. Pin, Valgrind-based ctgrind) for different inputs and
  assert they are identical.

## P-256 public key validation

Every received P-256 key is validated before use (SP 800-56A §5.6.2.3.3):

| Side    | Keys received                                     |
| ------- | ------------------------------------------------- |
| Enclave | `e_c` (handshake message 1)                       |
| Client  | `keys.s` (statement), `e_s` (handshake message 2) |

### Why

`sk_s` lives for the container lifetime. An invalid-curve attack sends a point on a weak curve; the
ECDH result then leaks `sk_s` modulo a small order. Repeated over many sessions, the attacker
recovers `sk_s` and can impersonate the enclave.

### Steps

1. Length is 65 B, first byte `0x04` (uncompressed). Reject `0x00` (infinity) and compressed `0x02`
   / `0x03`.
2. `x`, `y` are integers in `[0, p − 1]`.
3. `y² ≡ x³ − 3x + b (mod p)`.
4. P-256 has cofactor 1, so a point passing 1–3 has order `n`; no separate `nQ = O` check needed.

Reject the message on any failure; the error is the same `400` as a decrypt failure.

### Library notes

- Use the validated module's import path, which validates (aws-lc `EC_POINT_oct2point` +
  `EC_KEY_check_key`, WebCrypto `importKey("raw")`). Never do raw coordinate arithmetic.
- Confirm the chosen API validates; some low-level APIs accept arbitrary coordinates.
- Scalar multiplication must be constant time.
- Generate every `e` fresh from the validated DRBG; never reuse.
