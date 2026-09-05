// Exercises the bitwarden-fido WASM bridge from TypeScript.
//
// The point is the FFI boundary, not the FIDO2 logic: these tests confirm that a plain
// JavaScript object satisfies the `Fido2CredentialStore` / `Fido2UserInterface` interfaces,
// that callbacks reach it through `ThreadBoundRunner`, and that a throw arrives as a
// rejection rather than trapping the WebAssembly instance.

import { Fido2CredentialStore, Fido2UserInterface } from "@bitwarden/sdk-internal";

import { makeInitializedPasswordmanagerClient, makeStateBridge } from "../utils";

/** A store that records calls and returns empty results. */
function makeStore(overrides: Partial<Fido2CredentialStore> = {}) {
  const calls: string[] = [];
  const store: Fido2CredentialStore = {
    find_credentials: async () => {
      calls.push("find_credentials");
      return [];
    },
    all_credentials: async () => {
      calls.push("all_credentials");
      return [];
    },
    save_credential: async () => {
      calls.push("save_credential");
    },
    ...overrides,
  };
  return { store, calls };
}

/**
 * `is_verification_enabled` is a property, not a method: the SDK reads it once while
 * constructing the authenticator and caches it.
 */
function makeUserInterface(overrides: Partial<Fido2UserInterface> = {}) {
  return {
    check_user: async () => {
      throw new Error("not used");
    },
    pick_credential_for_authentication: async () => {
      throw new Error("not used");
    },
    check_user_and_pick_credential_for_creation: async () => {
      throw new Error("not used");
    },
    is_verification_enabled: true,
    ...overrides,
  } as unknown as Fido2UserInterface;
}

async function makeFido2Client() {
  return (await makeInitializedPasswordmanagerClient(makeStateBridge())).platform().fido2();
}

describe("fido2 bridge", () => {
  it("exposes the authenticator through platform().fido2()", async () => {
    const fido2 = await makeFido2Client();

    expect(fido2.authenticator(makeUserInterface(), makeStore().store)).toBeDefined();
  });

  it("routes credentials_for_autofill to the JavaScript credential store", async () => {
    const fido2 = await makeFido2Client();
    const { store, calls } = makeStore();

    const result = await fido2.authenticator(makeUserInterface(), store).credentials_for_autofill();

    expect(calls).toEqual(["all_credentials"]);
    expect(result).toEqual([]);
  });

  it("accepts is_verification_enabled as a plain property", async () => {
    const fido2 = await makeFido2Client();

    // Constructing the authenticator is what reads the property. A method would not satisfy
    // the interface, so reaching a result at all is the assertion.
    const result = await fido2
      .authenticator(makeUserInterface({ is_verification_enabled: false } as never), makeStore().store)
      .credentials_for_autofill();

    expect(result).toEqual([]);
  });

  it("surfaces a throwing callback as a rejection instead of trapping", async () => {
    const fido2 = await makeFido2Client();
    const { store } = makeStore({
      all_credentials: async () => {
        throw new Error("store exploded");
      },
    });

    await expect(
      fido2.authenticator(makeUserInterface(), store).credentials_for_autofill(),
    ).rejects.toBeDefined();
  });

  it("still works after a callback threw, so the instance was not poisoned", async () => {
    const fido2 = await makeFido2Client();
    const { store } = makeStore({
      all_credentials: async () => {
        throw new Error("store exploded");
      },
    });
    const authenticator = fido2.authenticator(makeUserInterface(), store);

    await expect(authenticator.credentials_for_autofill()).rejects.toBeDefined();

    const healthy = await fido2
      .authenticator(makeUserInterface(), makeStore().store)
      .credentials_for_autofill();
    expect(healthy).toEqual([]);
  });
});
