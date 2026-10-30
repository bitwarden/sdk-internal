// Captures the SDK's `WebAssembly.Memory`, which the wasm-bindgen Node output does not export.
//
//   import "./wasm-memory-probe" ──► wraps WebAssembly.Instance ──► SDK module instantiates ──► memory
//
// Import this before anything that imports `@bitwarden/sdk-internal`, so the wrapper is in place
// when the SDK instantiates its module.

let memory: WebAssembly.Memory | undefined;

const Instance = WebAssembly.Instance;
WebAssembly.Instance = new Proxy(Instance, {
  construct(target, args, newTarget) {
    const instance = Reflect.construct(target, args, newTarget) as WebAssembly.Instance;
    memory ??= Object.values(instance.exports).find(
      (value): value is WebAssembly.Memory => value instanceof WebAssembly.Memory,
    );
    return instance;
  },
});

/** The byte length of the SDK's linear memory, or undefined before the SDK is loaded. */
export function wasmMemoryBytes(): number | undefined {
  return memory?.buffer.byteLength;
}
