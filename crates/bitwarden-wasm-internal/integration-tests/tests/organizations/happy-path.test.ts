// Decrypts every committed organization vector's vault, as each of its members.
//
// This exercises a chain the user-vector suites never touch — account private key -> organization key ->
// per-item cipher key -> plaintext — and it does so once per member, because every member must reach
// byte-identical plaintext from their own differently-sealed copy of the same organization key.
//
// It matters in TypeScript rather than only in Rust for the same reason the vault suite does: the models
// cross the FFI boundary, and `organizationKeys` in particular crosses as a `Map`, which is a shape only
// the bindings impose.

import {
  memberVector,
  organizationCases,
  organizations,
  ORGANIZATION_TIMEOUT,
  validateOrganizationVaultFor,
} from "./vault-support";

describe("organization test vectors", () => {
  it("loads the expected set of vectors", () => {
    expect(organizations.map((vector) => vector.name).sort()).toEqual(["example-org"]);
  });

  describe.each(organizationCases)("%s", (_name, vector) => {
    it("holds a non-empty vault of organization-owned ciphers", () => {
      // Guards every decryption test below against being vacuous.
      expect(vector.vault.ciphers.length).toBeGreaterThan(0);
      for (const cipher of vector.vault.ciphers) {
        expect(cipher.encrypted.organizationId).toBe(vector.organizationId);
      }
    });

    it.each(vector.members.map((member, index) => [member.userVector, index] as const))(
      "decrypts the organization vault as %s",
      async (_userVectorName, index) => {
        await validateOrganizationVaultFor(vector, memberVector(vector, index));
      },
      ORGANIZATION_TIMEOUT,
    );
  });
});
