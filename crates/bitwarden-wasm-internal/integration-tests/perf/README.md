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

- `PERF_WASM_CPU`: wasm target features (default: the shipped `.wasm` features from `../build.sh`).
- `PERF_CARGO_ARGS`: extra cargo flags, e.g. `--config profile.release.package.argon2.opt-level=3`.

Set `PERF_LABEL` to write results to `perf/results/<label>/<task>.json`. Timings vary between
processes by a few percent; compare runs made back to back on an otherwise idle machine.

## Iterator harnesses

Compare decrypting a vault in one call (`decrypt_list_with_failures`) with `decrypt_list_iterable`,
which pulls encrypted ciphers from an async source a chunk at a time and yields one result per
cipher. The `CipherDecryptStream` and `CipherAsyncDecryptStream` handles, with explicit `next_item`
and `next_chunk` calls, serve as baselines. The async source resolves in a microtask; the cost of a
real IndexedDB is not modelled.

```sh
npm run perf -- iterator.perf      # time per mode
./perf/iterator-memory.sh          # WASM memory growth per mode, one process each
PERF_STREAM_MODE=iterable-results npm run perf -- iterator-memory   # a single mode
./perf/iterable-gc.sh              # whether iterables left early are reclaimed, with and without gc()
```

WASM memory never shrinks, so each memory run must be its own process. `npm run perf` runs the
memory harnesses once, in their default modes.
