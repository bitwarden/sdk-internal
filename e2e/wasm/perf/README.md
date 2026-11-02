# Performance harnesses

Benchmarks for the WASM SDK, run through the Node build with
[vitest bench](https://vitest.dev/guide/benchmarking). Excluded from `npm test`; files match
`perf/*.perf.ts`.

```sh
./perf/build.sh                    # release build of the Node target, with symbol names for profiling
npm run perf                       # run all harnesses
npm run perf -- unlock             # run one harness
npm run perf -- -t "v2 encryption" # run matching benchmarks only
npm run perf:profile               # same, writing a V8 CPU profile to perf/profiles/
```

`perf/build.sh` takes overrides to compare build configurations:

- `PERF_WASM_CPU`: wasm target features (default: the shipped `.wasm` features from
  `crates/bitwarden-wasm-internal/build.sh`).
- `PERF_CARGO_ARGS`: extra cargo flags, e.g. `--config profile.release.package.argon2.opt-level=3`.

Set `PERF_LABEL` to write results to `perf/results/<label>/<task>.json`. Timings vary between
processes by a few percent; compare runs made back to back on an otherwise idle machine.

`perf/build.sh` enables the `perf-baselines` cargo feature, which adds benchmark-only API variants
such as `decrypt_list_with_failures_eager`. Harnesses that call them need that build.

## Decrypt list

`decrypt-list.perf.ts` times `decrypt_list_with_failures` with its `Cipher[]` converted in full at
the boundary (`eager`) and a batch at a time inside the SDK (`batched`), after checking both give
the same result, with the same key order. It also times `decrypt_list_full_with_failures` (full
`CipherView`s) eager and batched.

`decrypt-list-memory.sh` measures the WASM memory growth of each mode, one process per mode, since
WASM memory never shrinks. Only the input is converted a batch at a time: in every mode the views
are collected in a Rust `Vec` and converted to JavaScript in full when the call returns. A `count`
mode decrypts batch by batch like `batched` but drops each view, so it shows the floor the input
path alone needs, and batched minus count is the memory the output takes. Each mode has a `full-`
counterpart for `CipherView` output. `PERF_DECRYPT_LIST_MODES` limits the run to some modes.

```sh
npm run perf -- decrypt-list.perf  # time
./perf/decrypt-list-memory.sh      # memory
```
