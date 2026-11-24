import { requireLiveConfig } from "../../live/config";

/** Live accounts are seeded, so live mode needs the server's seeder configured. */
describe("live configuration", () => {
  beforeEach(() => {
    vi.stubEnv("BW_LIVE_SERVER_URL", "https://vault.example.com");
    vi.stubEnv("BW_LIVE_SEEDER_URL", "");
    vi.stubEnv("BW_LIVE_SEEDER_USERNAME", "seeder");
    vi.stubEnv("BW_LIVE_SEEDER_PASSWORD", "not-a-real-password");
  });

  afterEach(() => vi.unstubAllEnvs());

  it("reads the seeder's settings", () => {
    // 1. Configure a seeder
    vi.stubEnv("BW_LIVE_SEEDER_URL", "http://seeder.example.com/");

    // 2. Verify the harness reaches it there
    expect(requireLiveConfig().seeder).toEqual({
      url: "http://seeder.example.com",
      username: "seeder",
      password: "not-a-real-password",
    });
  });

  it("refuses live mode without a seeder", () => {
    // 1. Configure no seeder, then verify the configuration is refused, naming what is missing
    expect(() => requireLiveConfig()).toThrow(/BW_LIVE_SEEDER_URL is not set/);
  });
});
