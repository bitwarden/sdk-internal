// SDK/WASM code relies on TextEncoder/TextDecoder being available globally
if (!globalThis.TextEncoder && typeof jest !== "undefined") {
  globalThis.TextEncoder = require("util").TextEncoder;
}
if (!globalThis.TextDecoder && typeof jest !== "undefined") {
  globalThis.TextDecoder = require("util").TextDecoder;
}

module.exports = require("./bitwarden_wasm_internal.js");
