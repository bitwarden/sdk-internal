# Example

Illustrative only; not used by the SDK.

1. Alice generates a key pair and publishes the public key.
2. Bob generates a symmetric key and encrypts it to Alice's public key.
3. Alice decrypts it with her private key.

```
Alice                         Bob
  | -------- pk_alice ------> |
  |                           | generate k
  | <- PKE_ENC(pk_alice, k) - |
  | PKE_DEC(sk_alice, ...)    |
```

## Model

[example.vp](example.vp)

Queries:

- `confidentiality? k`: only Alice and Bob learn `k`.
- `authentication? Bob -> Alice: e`: Alice knows `e` came from Bob.

Expected findings: both fail. Alice's public key is unauthenticated, so
an active attacker substitutes their own key and learns `k`. Anyone can
encrypt to a public key, so Alice cannot attribute `e` to Bob.
