# Verifpal dependency tracking

Tracking-only crate. It is never built or run. `cargo bin verifpal` builds upstream's own
`Cargo.lock` (`locked = true`), which lives outside this repo, so dependency scanners would not see
it. This crate's `Cargo.lock` mirrors upstream's at the pinned rev to make it visible.

It has its own `[workspace]`, is excluded from the root workspace, and is ignored by Renovate.
`scripts/check-verifpal-pin.py` fails CI if the rev or any locked version differs from upstream.

## Reseeding after a rev bump

```sh
curl -fsSL https://raw.githubusercontent.com/symbolicsoft/verifpal/<rev>/Cargo.lock \
  -o support/verifpal/Cargo.lock
(cd support/verifpal && cargo metadata --format-version 1 > /dev/null)
python3 scripts/check-verifpal-pin.py
```

`cargo metadata` only adds this crate and Verifpal's git source; every other entry stays as upstream
locked it.
