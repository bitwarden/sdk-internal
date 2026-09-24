// Integration coverage for the dev-only debug tree (see the `debug-capabilities`
// cargo feature). The `debug()` method exists only in a build made with
// `build.sh -d`; on a normal build it is absent, so this test skips itself
// rather than failing.

import { makePasswordManagerClient, makeStateBridge } from "./utils";

// The debug tree is untyped here on purpose: its `.d.ts` is only generated in a
// `-d` build, and this test must still type-check against a normal build.
type DebugCapable = { debug?: () => { state: () => { types: () => string[] } } };

describe("debug state browse", () => {
  it("lists the SDK-managed repositories on the memory-backed client", () => {
    // The wasm/mobile bindings build a memory-backed registry with no
    // client-managed repositories wired up here, so before the fix `types()`
    // was empty. The SDK-managed set can only appear once `debug()` registers
    // the migration shims.
    const client = makePasswordManagerClient(makeStateBridge()) as unknown as DebugCapable;

    if (typeof client.debug !== "function") {
      return; // Not a debug-capabilities build; nothing to exercise.
    }

    const types = client.debug().state().types();

    expect(types).toEqual(
      expect.arrayContaining(["Cipher", "Folder", "Setting", "OrganizationSharedKey", "Send"]),
    );
  });
});
