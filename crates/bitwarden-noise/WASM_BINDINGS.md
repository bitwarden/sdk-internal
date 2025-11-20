# WASM Bindings for bitwarden-noise

## Overview

The `bitwarden-noise` crate is now fully compatible with `wasm-bindgen` through a handle-based architecture. Since the underlying `snow` crate types (`HandshakeState` and `TransportState`) don't support Serde serialization, we use an opaque handle system to manage protocol instances.

## Architecture

### Handle-Based Design

Instead of exposing `NoiseProtocol` directly across the WASM boundary (which would fail due to non-serializable types), we:

1. Store `NoiseProtocol` instances in a global `ProtocolStore`
2. Return `NoiseProtocolHandle` (a simple `u32` wrapper) to WASM clients
3. Use the handle to reference the protocol instance in subsequent operations

This pattern is similar to file descriptors in Unix systems - the handle is just an opaque reference to an internal resource.

### Type Safety

The `NoiseProtocolHandle` type:
- Is a newtype wrapper around `u32` for type safety
- Implements `Serialize`/`Deserialize` for WASM ABI compatibility
- Uses `Tsify` to generate TypeScript types when the `wasm` feature is enabled
- Cannot be forged or manipulated (invalid handles return errors)

## Usage

### TypeScript/JavaScript Example

```typescript
import {
  generate_keypair,
  create_noise_protocol,
  noise_write_message,
  noise_read_message,
  noise_split,
  noise_encrypt_message,
  noise_decrypt_message,
  noise_is_handshake_complete,
  destroy_noise_protocol,
  NoiseProtocolHandle,
  Keypair,
} from './bitwarden_wasm_internal';

// Generate keypairs
const initiatorKeypair = generate_keypair();
const responderKeypair = generate_keypair();

// Create protocol instances (returns handles)
const initiator = create_noise_protocol(
  true,  // is_initiator
  initiatorKeypair.secret_key,
  null   // no PSK
);

const responder = create_noise_protocol(
  false, // is_responder
  responderKeypair.secret_key,
  null
);

// Perform handshake
const msg1 = noise_write_message(initiator, null);
noise_read_message(responder, msg1);

const msg2 = noise_write_message(responder, null);
noise_read_message(initiator, msg2);

const msg3 = noise_write_message(initiator, null);
noise_read_message(responder, msg3);

// Complete handshake
noise_split(initiator);
noise_split(responder);

// Now can encrypt/decrypt
const plaintext = new TextEncoder().encode("Hello, Noise!");
const ciphertext = noise_encrypt_message(initiator, plaintext);
const decrypted = noise_decrypt_message(responder, ciphertext);

// Clean up when done
destroy_noise_protocol(initiator);
destroy_noise_protocol(responder);
```

### Rust Example

```rust
use bitwarden_noise::{
    create_noise_protocol,
    destroy_noise_protocol,
    generate_keypair,
    noise_write_message,
    noise_read_message,
    noise_split,
    noise_encrypt_message,
    noise_decrypt_message,
};

// Generate keypairs
let initiator_kp = generate_keypair().unwrap();
let responder_kp = generate_keypair().unwrap();

// Create protocol instances
let initiator = create_noise_protocol(
    true,
    Some(initiator_kp.secret_key()),
    None
).unwrap();

let responder = create_noise_protocol(
    false,
    Some(responder_kp.secret_key()),
    None
).unwrap();

// Perform handshake (XX pattern: 3 messages)
let msg1 = noise_write_message(initiator, None).unwrap();
noise_read_message(responder, msg1).unwrap();

let msg2 = noise_write_message(responder, None).unwrap();
noise_read_message(initiator, msg2).unwrap();

let msg3 = noise_write_message(initiator, None).unwrap();
noise_read_message(responder, msg3).unwrap();

// Complete handshake
noise_split(initiator).unwrap();
noise_split(responder).unwrap();

// Encrypt/decrypt messages
let plaintext = b"Secret message";
let ciphertext = noise_encrypt_message(initiator, plaintext.to_vec()).unwrap();
let decrypted = noise_decrypt_message(responder, ciphertext).unwrap();

assert_eq!(decrypted, plaintext);

// Clean up
destroy_noise_protocol(initiator).unwrap();
destroy_noise_protocol(responder).unwrap();
```

## API Reference

### `generate_keypair() -> Result<Keypair, NoiseProtocolError>`
Generates a new Curve25519 keypair for use with the Noise protocol.

### `create_noise_protocol(is_initiator: bool, static_secret_key: Option<Vec<u8>>, psk: Option<Vec<u8>>) -> Result<NoiseProtocolHandle, NoiseProtocolError>`
Creates a new Noise protocol instance and returns a handle to it.

**Parameters:**
- `is_initiator`: `true` if this is the connection initiator, `false` if responder
- `static_secret_key`: Optional 32-byte secret key (generates new one if `None`)
- `psk`: Optional 32-byte pre-shared key for XXpsk3 pattern (uses XX pattern if `None`)

### `noise_write_message(handle: NoiseProtocolHandle, payload: Option<Vec<u8>>) -> Result<Vec<u8>, NoiseProtocolError>`
Writes a handshake message. Returns the bytes to send to the peer.

### `noise_read_message(handle: NoiseProtocolHandle, message: Vec<u8>) -> Result<Vec<u8>, NoiseProtocolError>`
Reads a handshake message from the peer. Returns any payload contained in the message.

### `noise_split(handle: NoiseProtocolHandle) -> Result<(), NoiseProtocolError>`
Completes the handshake and transitions to transport mode. Must be called after all handshake messages are exchanged.

### `noise_encrypt_message(handle: NoiseProtocolHandle, plaintext: Vec<u8>) -> Result<Vec<u8>, NoiseProtocolError>`
Encrypts a message. Can only be called after the handshake is complete.

### `noise_decrypt_message(handle: NoiseProtocolHandle, ciphertext: Vec<u8>) -> Result<Vec<u8>, NoiseProtocolError>`
Decrypts a message. Can only be called after the handshake is complete.

### `noise_is_handshake_complete(handle: NoiseProtocolHandle) -> Result<bool, NoiseProtocolError>`
Returns `true` if the handshake is complete and the protocol is in transport mode.

### `destroy_noise_protocol(handle: NoiseProtocolHandle) -> Result<(), NoiseProtocolError>`
Destroys a protocol instance and frees its resources. The handle becomes invalid after this call.

## Thread Safety

The global `ProtocolStore` uses `Arc<Mutex<>>` for thread-safe access. In WASM environments (which are single-threaded), the mutex overhead is minimal.

## Security Considerations

1. **Handle Validation**: All operations validate the handle before accessing the protocol instance
2. **No Handle Reuse**: Destroyed handles cannot be reused (IDs increment monotonically)
3. **Memory Safety**: The Rust type system ensures no use-after-free or double-free bugs
4. **State Machine**: The protocol enforces correct state transitions (e.g., can't encrypt before handshake)

## Implementation Details

### Why not serialize the protocol state?

The `snow` crate's `HandshakeState` and `TransportState` types contain complex internal state including:
- Cipher state (AES-GCM or ChaCha20-Poly1305)
- Hash state (SHA256, SHA512, or BLAKE2)
- DH key material
- Nonces and counters

These types don't implement Serde and would be complex to serialize correctly while maintaining security properties. The handle-based approach is simpler, more performant, and maintains type safety.

### Memory Management

The `ProtocolStore` grows as new protocol instances are created. In long-running applications, make sure to call `destroy_noise_protocol()` when done with a protocol instance to prevent memory leaks.

### Error Handling

All operations return `Result<T, NoiseProtocolError>` for proper error handling. Common errors:
- `InvalidHandle`: The handle doesn't reference a valid protocol instance
- `HandshakeNotComplete`: Tried to encrypt/decrypt before completing handshake
- `UseEncryptInstead`/`UseDecryptInstead`: Tried to use handshake methods after split
- `LockPoisoned`: Internal mutex was poisoned (rare, indicates panic in another thread)
