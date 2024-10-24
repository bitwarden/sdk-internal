// https://stackoverflow.com/a/47880734
const supported = (() => {
  try {
    if (typeof WebAssembly === "object" && typeof WebAssembly.instantiate === "function") {
      const module = new WebAssembly.Module(
        Uint8Array.of(0x0, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00),
      );
      if (module instanceof WebAssembly.Module) {
        return new WebAssembly.Instance(module) instanceof WebAssembly.Instance;
      }
    }
  } catch (e) {}
  return false;
})();

import { __wbg_set_wasm } from "./bitwarden_wasm_internal_bg.js";

let loaded_wasm;

export async function init(wasm) {
  if (loaded_wasm) {
    return;
  }

  // If the caller provided a wasm module, use it for backwards compatibility.
  if (wasm) {
    loaded_wasm = wasm;
  } else if (supported) {
    loaded_wasm = await import("./bitwarden_wasm_internal_bg.wasm");
  } else {
    loaded_wasm = await import("./bitwarden_wasm_internal_bg.wasm.js");
  }

  __wbg_set_wasm(loaded_wasm);
}

export * from "./bitwarden_wasm_internal_bg.js";
