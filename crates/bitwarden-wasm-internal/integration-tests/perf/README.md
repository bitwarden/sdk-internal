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

- `PERF_WASM_CPU`: wasm target features (default `-Ctarget-cpu=mvp`, as in `../build.sh`).
- `PERF_CARGO_ARGS`: extra cargo flags, e.g. `--config profile.release.package.argon2.opt-level=3`.

Set `PERF_LABEL` to write results to `perf/results/<label>/<task>.json`. Timings vary between
processes by a few percent; compare runs made back to back on an otherwise idle machine.
