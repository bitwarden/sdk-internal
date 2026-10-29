# HIBP Bulk

Check many password hashes against Have I Been Pwned in one session, without revealing them to
anyone outside an attested enclave.

Specification only; no implementation yet.

| Document                                                                                | Content                                                |
| --------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| [overview.md](docs/overview.md)                                                         | Problem, solution, architecture, attestation           |
| [hibp-bulk-proto.md](docs/hibp-bulk-proto.md)                                           | Batch query / response messages                        |
| [enclave-comms-proto.md](docs/enclave-comms-proto.md)                                   | Attested Noise channel to the enclave                  |
| [hibp-bulk-proto-security-definitions.md](docs/hibp-bulk-proto-security-definitions.md) | Actors, assets, goals, assumptions, leakage            |
| [implementation-guidance.md](docs/implementation-guidance.md)                           | Oblivious lookups, side channels, P-256 key validation |
| [comparison.md](docs/comparison.md)                                                     | Range API vs bulk protocol, data sizes                 |
