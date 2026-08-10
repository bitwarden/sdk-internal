// The state a member is in before their client has loaded the organization key.
//
// A client that belongs to an organization but has not yet called `initialize_org_crypto` holds no
// organization key at all, so an organization cipher must refuse to decrypt rather than fall back to the
// user key and produce something.

import { unlockVector } from "../test-vectors/unlock";
import { memberVector, organizationCases, ORGANIZATION_TIMEOUT } from "./vault-support";

describe("organization test vectors", () => {
  describe.each(organizationCases)("%s", (_name, vector) => {
    it(
      "cannot reach organization ciphers without the organization key",
      async () => {
        const user = memberVector(vector, 0);
        // The state a user who belongs to an organization is in before their client loads its key.
        const client = await unlockVector(user, user.unlockMethods[0], { organizations: false });

        await expect(
          client.vault().ciphers().decrypt(vector.vault.ciphers[0].encrypted),
        ).rejects.toBeDefined();
      },
      ORGANIZATION_TIMEOUT,
    );
  });
});
