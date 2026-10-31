import { AutotypeRunningApp, Source, autotypeRequestGetCredentials } from "@bitwarden/sdk-internal";

import { makeMockAutotypeRenderDriver, setupRenderHandlerPair } from "./autotype-test-utils";

const APP: AutotypeRunningApp = { name: "Example", path: "/Applications/Example.app" };

describe("autotype get credentials ipc", () => {
  it("returns the matching credentials", async () => {
    const driver = makeMockAutotypeRenderDriver({
      getCredentials: async () => ({
        username: "user@example.com",
        password: "correct-horse",
      }),
    });
    const { main } = await setupRenderHandlerPair(driver);

    const response = await autotypeRequestGetCredentials(main, APP);

    expect(response.credentials).toEqual({
      username: "user@example.com",
      password: "correct-horse",
    });
    expect(driver.getCredentialsCalls).toEqual([APP]);
  });

  // Only the username and password cross back to main, even if the driver hands over more of the
  // vault item.
  it("sends only the username and password, dropping other fields the driver returns", async () => {
    const driver = makeMockAutotypeRenderDriver({
      getCredentials: async () => ({
        username: "user@example.com",
        password: "correct-horse",
        totp: "123456",
        metadata: { id: 7, pid: 4242 },
      }),
    });
    const { main } = await setupRenderHandlerPair(driver);

    const response = await autotypeRequestGetCredentials(main, APP);

    // `toEqual` fails on extra keys, so this proves nothing else reached main.
    expect(response.credentials).toEqual({
      username: "user@example.com",
      password: "correct-horse",
    });
  });

  // No match is a normal reply, not an error.
  it.each<[string, unknown]>([
    ["undefined", undefined],
    ["null", null],
  ])("reports no match when the driver returns %s", async (_label, result) => {
    const driver = makeMockAutotypeRenderDriver({ getCredentials: async () => result });
    const { main } = await setupRenderHandlerPair(driver);

    await expect(autotypeRequestGetCredentials(main, APP)).resolves.toEqual({
      credentials: undefined,
    });
    expect(driver.getCredentialsCalls).toHaveLength(1);
  });

  it("reports no match when the driver throws", async () => {
    const driver = makeMockAutotypeRenderDriver({
      getCredentials: async () => {
        throw new Error("vault locked");
      },
    });
    const { main } = await setupRenderHandlerPair(driver);

    // A throwing driver never produces credentials, and the request resolves rather than
    // rejecting.
    await expect(autotypeRequestGetCredentials(main, APP)).resolves.toEqual({
      credentials: undefined,
    });
  });

  it.each<[string, unknown]>([
    ["a match without a password", { username: "user@example.com" }],
    ["a bare string", "correct-horse"],
    ["a match with a non-string password", { username: "user@example.com", password: 123 }],
  ])("reports no match when the driver returns %s", async (_label, result) => {
    const driver = makeMockAutotypeRenderDriver({ getCredentials: async () => result });
    const { main } = await setupRenderHandlerPair(driver);

    await expect(autotypeRequestGetCredentials(main, APP)).resolves.toEqual({
      credentials: undefined,
    });
  });

  it("keeps concurrent requests matched to their own replies", async () => {
    // Each reply is derived from its request's app, so a crossed correlation would surface as a
    // mismatched ordering below.
    const driver = makeMockAutotypeRenderDriver({
      getCredentials: async (app) => ({
        username: `user-${app.name}`,
        password: `password-${app.name}`,
      }),
    });
    const { main } = await setupRenderHandlerPair(driver);

    const responses = await Promise.all(
      ["one", "two", "three"].map((name) =>
        autotypeRequestGetCredentials(main, { name, path: `/Applications/${name}.app` }),
      ),
    );

    expect(responses.map((r) => r.credentials?.username)).toEqual([
      "user-one",
      "user-two",
      "user-three",
    ]);
    expect(responses.map((r) => r.credentials?.password)).toEqual([
      "password-one",
      "password-two",
      "password-three",
    ]);
  });

  // Main forwards native-messaging traffic to the render process under its original source,
  // labeled the way desktop's `sourceFor()` labels it. Only main itself may request credentials.
  it.each<[string, Source]>([
    ["the browser extension", { BrowserBackground: { id: { Id: 1 } } }],
    ["the CLI", { Cli: { id: { Id: 1 } } }],
  ])("refuses a request sent by %s without calling the driver", async (_label, source) => {
    const driver = makeMockAutotypeRenderDriver({
      getCredentials: async () => ({
        username: "user@example.com",
        password: "correct-horse",
      }),
    });
    const { main: peer } = await setupRenderHandlerPair(driver, source);

    await expect(autotypeRequestGetCredentials(peer, APP)).resolves.toEqual({
      credentials: undefined,
    });
    expect(driver.getCredentialsCalls).toEqual([]);
  });
});
