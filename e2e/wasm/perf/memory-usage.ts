// Memory readings shared by the memory harnesses.

const MiB = 1024 * 1024;

/**
 * WASM memory plus other non-ArrayBuffer external memory, in bytes. Node counts WASM memory in
 * `external` but not in `arrayBuffers`, so their difference excludes the JS copies of the ciphers
 * and views.
 */
export function wasmMemory(): number {
  const { external, arrayBuffers } = process.memoryUsage();
  return external - arrayBuffers;
}

/** `bytes` in MiB, rounded to `digits` decimals. */
export function mib(bytes: number, digits = 1): number {
  return Number((bytes / MiB).toFixed(digits));
}
