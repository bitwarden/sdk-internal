import {
  AppMetadata,
  AutotypeRunningApp,
  Source,
  autotypeRequestExecute,
} from "@bitwarden/sdk-internal";

import { makeMockAutotypeRenderDriver, setupRenderHandlerPair } from "./autotype-test-utils";

const APP: AutotypeRunningApp = { name: "Example", path: "/Applications/Example.app" };
const METADATA: AppMetadata = { id: 7, pid: 4242 };

describe("autotype execute ipc", () => {
  it("returns the matching credentials with the request's metadata", async () => {
    const driver = makeMockAutotypeRenderDriver({
      executeAutotype: async (_app, metadata) => ({
        metadata,
        username: "user@example.com",
        password: "correct-horse",
      }),
    });
    const { main } = await setupRenderHandlerPair(driver);

    const response = await autotypeRequestExecute(main, APP, METADATA);

    expect(response.matched).toEqual({
      metadata: METADATA,
      username: "user@example.com",
      password: "correct-horse",
    });
    expect(driver.executeAutotypeCalls).toEqual([{ app: APP, metadata: METADATA }]);
  });

  // No match is a normal reply, not an error.
  it.each<[string, unknown]>([
    ["undefined", undefined],
    ["null", null],
  ])("reports no match when the driver returns %s", async (_label, result) => {
    const driver = makeMockAutotypeRenderDriver({ executeAutotype: async () => result });
    const { main } = await setupRenderHandlerPair(driver);

    await expect(autotypeRequestExecute(main, APP, METADATA)).resolves.toEqual({
      matched: undefined,
    });
    expect(driver.executeAutotypeCalls).toHaveLength(1);
  });

  it("reports no match when the driver throws", async () => {
    const driver = makeMockAutotypeRenderDriver({
      executeAutotype: async () => {
        throw new Error("vault locked");
      },
    });
    const { main } = await setupRenderHandlerPair(driver);

    // A throwing driver never produces credentials, and the request resolves rather than
    // rejecting.
    await expect(autotypeRequestExecute(main, APP, METADATA)).resolves.toEqual({
      matched: undefined,
    });
  });

  it.each<[string, unknown]>([
    ["a match without a password", { metadata: METADATA, username: "user@example.com" }],
    ["a bare string", "correct-horse"],
    [
      "a match with a non-number id",
      { metadata: { id: "7", pid: 4242 }, username: "user@example.com", password: "correct-horse" },
    ],
  ])("reports no match when the driver returns %s", async (_label, result) => {
    const driver = makeMockAutotypeRenderDriver({ executeAutotype: async () => result });
    const { main } = await setupRenderHandlerPair(driver);

    await expect(autotypeRequestExecute(main, APP, METADATA)).resolves.toEqual({
      matched: undefined,
    });
  });

  it("keeps concurrent requests matched to their own replies", async () => {
    // Each reply is derived from its request's metadata, so a crossed correlation would surface as
    // a mismatched ordering below.
    const driver = makeMockAutotypeRenderDriver({
      executeAutotype: async (_app, metadata) => ({
        metadata,
        username: `user-${metadata.id}`,
        password: `password-${metadata.id}`,
      }),
    });
    const { main } = await setupRenderHandlerPair(driver);

    const responses = await Promise.all(
      [1, 2, 3].map((id) => autotypeRequestExecute(main, APP, { id, pid: 100 + id })),
    );

    expect(responses.map((r) => r.matched?.metadata)).toEqual([
      { id: 1, pid: 101 },
      { id: 2, pid: 102 },
      { id: 3, pid: 103 },
    ]);
    expect(responses.map((r) => r.matched?.username)).toEqual(["user-1", "user-2", "user-3"]);
  });

  // Main forwards native-messaging traffic to the render process under its original source,
  // labeled the way desktop's `sourceFor()` labels it. Only main itself may request credentials.
  it.each<[string, Source]>([
    ["the browser extension", { BrowserBackground: { id: { Id: 1 } } }],
    ["the CLI", { Cli: { id: { Id: 1 } } }],
  ])("refuses a request sent by %s without calling the driver", async (_label, source) => {
    const driver = makeMockAutotypeRenderDriver({
      executeAutotype: async (_app, metadata) => ({
        metadata,
        username: "user@example.com",
        password: "correct-horse",
      }),
    });
    const { main: peer } = await setupRenderHandlerPair(driver, source);

    await expect(autotypeRequestExecute(peer, APP, METADATA)).resolves.toEqual({
      matched: undefined,
    });
    expect(driver.executeAutotypeCalls).toEqual([]);
  });
});
