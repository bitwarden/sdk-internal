import { randomUUID } from "node:crypto";

import { isExportError, type Cipher, type CipherId } from "@bitwarden/sdk-internal";

import { generateVault } from "../../perf/vault-generator";
import { makeStateBridge, makeV2AccountClient } from "../utils";

async function exportedVault(size: number) {
  const client = await makeV2AccountClient(makeStateBridge());
  // An export leaves out a cipher without an id.
  const views = generateVault(size).map((view) => ({
    ...view,
    id: randomUUID() as unknown as CipherId,
  }));
  const ciphers = (await client.vault().ciphers().encrypt_list(views)).map((ctx) => ctx.cipher);
  return { exporters: client.exporters(), views, ciphers };
}

// `export_vault` converts its `Cipher[]` one cipher at a time inside the SDK.
describe("ExporterClient.export_vault", () => {
  it("exports every cipher of the list, in order", async () => {
    const { exporters, views, ciphers } = await exportedVault(600);

    const exported = JSON.parse(await exporters.export_vault([], ciphers, "Json"));

    expect(exported.items.map((item: { name: string }) => item.name)).toEqual(
      views.map((view) => view.name),
    );
  });

  it("rejects with InvalidInput when an entry is not a cipher", async () => {
    const { exporters, ciphers } = await exportedVault(2);
    const input = [ciphers[0], { not: "a cipher" }, ciphers[1]] as unknown as Cipher[];

    const error = await exporters.export_vault([], input, "Json").then(
      () => undefined,
      (thrown: unknown) => thrown,
    );

    expect(isExportError(error) ? error.variant : undefined).toBe("InvalidInput");
    expect((error as Error).message).toContain("Item 1 of the list is invalid");
  });

  it("names the entry's index when the invalid entry comes after the others", async () => {
    const { exporters, ciphers } = await exportedVault(300);
    const input = [...ciphers, { not: "a cipher" }] as unknown as Cipher[];

    const error = await exporters.export_vault([], input, "Json").then(
      () => undefined,
      (thrown: unknown) => thrown,
    );

    expect(isExportError(error) ? error.variant : undefined).toBe("InvalidInput");
    expect((error as Error).message).toContain("Item 300 of the list is invalid");
  });
});
