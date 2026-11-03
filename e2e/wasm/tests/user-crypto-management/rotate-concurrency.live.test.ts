// Key rotation under contention against a real server.
//
// Opt-in through `BW_LIVE_SERVER_URL`; skipped otherwise. See `live/config.ts` and the Readme.

import { describeLoginFailure, liveConfig, requireLiveConfig } from "../../live/config";
import { liveHarness, type TestHarness } from "../../test-harness";
import { rotationConcurrencySuite } from "./rotate-concurrency-suite";

const describeLive = liveConfig() === undefined ? describe.skip : describe;

describeLive("rotate user keys under contention (live server)", () => {
  let harness: TestHarness;

  beforeEach(() => {
    const live = requireLiveConfig();
    harness = liveHarness(live.settings, live.loginRequest);
  });

  afterEach(() => harness.restore());

  rotationConcurrencySuite(async () => {
    const live = requireLiveConfig();

    return {
      email: live.email,
      password: live.password,
      newClient: () => {
        const client = harness.newClientEmulator();
        const login = client.login.bind(client);
        client.login = async (...args) => {
          try {
            await login(...args);
          } catch (error) {
            throw new Error(describeLoginFailure(error));
          }
        };

        return client;
      },
    };
  });
});
