import { requireLiveConfig } from "../../live/config";

const SEEDER = {
  BW_LIVE_SEEDER_URL: "http://seeder.example.com",
  BW_LIVE_SEEDER_USERNAME: "seeder",
  BW_LIVE_SEEDER_PASSWORD: "not-a-real-password",
};

/**
 * Where live test accounts come from is configured, never detected: the seeder unless
 * `BW_LIVE_ACCOUNTS` says `register`.
 */
describe("live account source", () => {
  beforeEach(() => {
    vi.stubEnv("BW_LIVE_SERVER_URL", "https://vault.example.com");
    vi.stubEnv("BW_LIVE_SECRET", "a secret for these tests");
    vi.stubEnv("BW_LIVE_ACCOUNTS", "");
    for (const name of Object.keys(SEEDER)) {
      vi.stubEnv(name, "");
    }
  });

  afterEach(() => vi.unstubAllEnvs());

  function stubSeeder(): void {
    for (const [name, value] of Object.entries(SEEDER)) {
      vi.stubEnv(name, value);
    }
  }

  it("takes accounts from the seeder by default", () => {
    // 1. Configure a seeder and no source
    stubSeeder();

    // 2. Verify the seeder is the source
    expect(requireLiveConfig().accountSource).toBe("seeder");
  });

  it("refuses the default source when no seeder is configured, naming the way out", () => {
    // 1. Configure neither a seeder nor a source, then verify the configuration is refused
    expect(() => requireLiveConfig()).toThrow(/BW_LIVE_ACCOUNTS=register/);
  });

  it("registers accounts when told to, with no seeder needed", () => {
    // 1. Ask for registration, with no seeder
    vi.stubEnv("BW_LIVE_ACCOUNTS", "register");

    // 2. Verify registration is the source
    expect(requireLiveConfig().accountSource).toBe("register");
  });

  it("refuses a source it does not know", () => {
    // 1. Ask for an unknown source, then verify the configuration is refused
    stubSeeder();
    vi.stubEnv("BW_LIVE_ACCOUNTS", "detect");

    expect(() => requireLiveConfig()).toThrow(/takes seeder or register/);
  });
});
