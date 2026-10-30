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

## Memory

`memory.ts` is the memory counterpart of `bench.ts`. `measureMemory(name, fn)` reports how much the
SDK's WASM linear memory and the JS heap grow over one call of `fn`, with garbage collected before
and after, and prints the result as a table, along with the `params` passed in its options. With
`PERF_LABEL` set it also writes it to `perf/results/<label>/<name>.json`.

```ts
test("decrypt_list_with_failures memory", async () => {
  const { ciphers, vault } = await encryptedVault(VAULT_SIZE, SETUP_CHUNK);
  const { result } = await measureMemory(
    "decrypt-list-memory",
    () => ciphers.decrypt_list_with_failures(vault),
    { params: { vaultSize: VAULT_SIZE } },
  );
  strictEqual(result.successes.length, VAULT_SIZE);
});
```

WASM linear memory never shrinks, so its growth over `fn` is the peak the SDK needed for it. That
only holds if nothing earlier in the process grew it further, so each harness file makes a single
`measureMemory` call; vitest runs each file in its own process. Growth that setup already caused is
invisible to `fn`, which is why the result reports it as `setupMiB`; keep the peak of setup small,
for example by encrypting a vault in small calls.

The vitest config loads `memory.ts` as a setup file, so it captures the SDK's `WebAssembly.Memory`
when the SDK loads, and passes `--expose-gc` to the harness processes. For a series of readings
rather than one measurement, `sampleMemory` and `collectGarbage` are exported too.

## Decrypt list

`decrypt-list.perf.ts` times `decrypt_list_with_failures` (`CipherListView` output) and
`decrypt_list_full_with_failures` (full `CipherView`s) over a vault of ciphers with cipher keys.
`decrypt-list-memory.perf.ts` and `decrypt-list-full-memory.perf.ts` measure the memory of each.

```sh
npm run perf -- decrypt-list.perf  # time
npm run perf -- memory             # memory, one process per harness file
```

Compare builds by running the same harness with a different `PERF_LABEL` for each.

## Iterator harnesses

Compare listing the vault from state in one call (`list`) with `list_iterable`, which reads the
cipher repository a chunk at a time and yields one result per cipher, and with decrypting a vault
array the client passes in (`decrypt_list_with_failures`). The state is a client-managed repository
in JavaScript, registered as a web client registers its own. They share their setup with the decrypt
list harnesses.

```sh
npm run perf -- iterator.perf      # time per mode
./perf/iterator-memory.sh          # WASM memory growth per mode, one process each
PERF_STREAM_MODE=list-iterable npm run perf -- iterator-memory   # a single mode
./perf/iterable-gc.sh              # whether iterables left early are reclaimed, with and without gc()
```

WASM memory never shrinks, so each memory run must be its own process. `npm run perf` runs the
memory harnesses once, in their default modes.
