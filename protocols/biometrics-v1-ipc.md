# Biometrics V1 IPC (deprecated)

IPC channel between the browser extension and the desktop app for
biometric unlock.

1. Extension generates an ephemeral key pair and sends the public key.
2. Desktop generates a symmetric key, wraps it to the public key (RSA)
   and sends it back.
3. Both sides exchange AEAD-encrypted messages under the symmetric key.

```
Extension                         Desktop
  | -------- sessionPublicKey ----> |
  |                                 | generate symmetricKey
  | <-------- wrappedKey ---------- |
  | unwrap symmetricKey             |
  | <---- AEAD(message1) ---------- |
  | ----- AEAD(message2) ---------> |
```

## Model

[biometrics-v1-ipc.vp](biometrics-v1-ipc.vp)

Passive attacker: models forensic analysis of a stolen device, not
active IPC tampering. RSA is modeled as `KEM_ENCAP`/`KEM_DECAP`, since
Verifpal has no RSA primitive.

Queries:

- `confidentiality? message1`, `confidentiality? message2`
- `authentication? Desktop -> Extension: packet1`
- `authentication? Extension -> Desktop: packet2`

Replays are not prevented per message; the application rejects messages
outside a 10s wall-clock window.
