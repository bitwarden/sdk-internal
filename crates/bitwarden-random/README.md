# Bitwarden Random

Provides an abstraction to provide the single rng impl for the sdk. This can be seeded if the
`dangerous-seeded-rng-for-testing` feature is enabled, but by default uses the OS CRNG.
