import {
  CipherType,
  isEncryptError,
  type CipherView,
  type PasswordManagerClient,
} from "@bitwarden/sdk-internal";

import { generateVault } from "../../perf/vault-generator";
import { makeInitializedPasswordmanagerClient, makeStateBridge, rejection } from "../utils";

/** How long `encrypt_list` gets to settle before the test reports it as hanging. */
const SETTLE_TIMEOUT_MS = 2_000;

/** Fails with a clear message if `promise` has not settled within `ms`. */
function settlesWithin<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`promise did not settle within ${ms} ms`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

/**
 * An SSH key view without a private key, as a Bitwarden JSON import can carry. `privateKey` is
 * required, so the view does not convert to the SDK's `CipherView`.
 */
function sshKeyWithoutPrivateKey(view: CipherView): CipherView {
  return {
    ...view,
    type: CipherType.SshKey,
    login: undefined,
    sshKey: {
      privateKey: null,
      publicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEvE9m9tL0YHW0Z9cZ0r1w0q8XQh2g1M0b0bU5i3eX7g",
      fingerprint: "SHA256:Pm9Kq9t7s7mQ3oGZr9pYq1r0aW1nKkY0c8m0w5Jz0Xk",
    },
  } as unknown as CipherView;
}

// `encrypt_list` converts its `CipherView[]` inside the SDK, so a view that does not convert
// rejects the returned promise. Converted as a plain `Vec<CipherView>`, the conversion threw inside
// the promise wasm-bindgen returns for an async export, and the promise never settled.
describe("CiphersClient encrypt_list", () => {
  let client: PasswordManagerClient;

  beforeAll(async () => {
    client = await makeInitializedPasswordmanagerClient(makeStateBridge());
  });

  it("encrypts every view of a valid list", async () => {
    const result = await settlesWithin(
      client.vault().ciphers().encrypt_list(generateVault(3)),
      SETTLE_TIMEOUT_MS,
    );

    expect(result).toHaveLength(3);
  });

  it("rejects, rather than never settling, when a view does not convert", async () => {
    const [valid, other] = generateVault(2);

    const error = await settlesWithin(
      rejection(
        client
          .vault()
          .ciphers()
          .encrypt_list([valid, sshKeyWithoutPrivateKey(other)]),
        isEncryptError,
      ),
      SETTLE_TIMEOUT_MS,
    );

    expect(error.variant).toBe("InvalidInput");
    // The index of the invalid view, which is all a caller needs to find it.
    expect(error.message).toContain("Item 1 ");
  });

  it("still encrypts after rejecting an invalid list", async () => {
    const [valid, other] = generateVault(2);
    await settlesWithin(
      rejection(
        client
          .vault()
          .ciphers()
          .encrypt_list([valid, sshKeyWithoutPrivateKey(other)]),
        isEncryptError,
      ),
      SETTLE_TIMEOUT_MS,
    );

    const result = await settlesWithin(
      client.vault().ciphers().encrypt_list(generateVault(1)),
      SETTLE_TIMEOUT_MS,
    );

    expect(result).toHaveLength(1);
  });
});
