import {
  AccessCondition,
  AccessRuleAddEditRequest,
  AccessRuleError,
  AccessRuleView,
  init_sdk,
  is_valid_cidr,
  PasswordManagerClient,
  TokenProvider,
} from "@bitwarden/commercial-sdk-internal";

// Targets the WASM surface exposed by `client.commercial().pam().access_rules()`
// (crates/bitwarden-wasm-internal behind the `bitwarden-license` feature, backed by
// bitwarden_license/bitwarden-pam). Requires the commercial artifact: build with
// `./crates/bitwarden-wasm-internal/build.sh -b` and `npm install` in this directory.
describe("PAM access rules WASM surface", () => {
  function makeCommercialClient(): PasswordManagerClient {
    init_sdk();

    const tokens: TokenProvider = {
      get_access_token: async () => undefined,
    };

    return new PasswordManagerClient(tokens);
  }

  describe("client.commercial().pam().access_rules() chain", () => {
    it("commercial() returns a non-null commercial client", () => {
      const client = makeCommercialClient();

      expect(client.commercial()).toBeDefined();
    });

    it("commercial().pam() returns a non-null PAM client", () => {
      const client = makeCommercialClient();

      expect(client.commercial().pam()).toBeDefined();
    });

    it("commercial().pam().access_rules() returns a non-null access rules client", () => {
      const client = makeCommercialClient();

      const accessRules = client.commercial().pam().access_rules();

      expect(accessRules).toBeDefined();
    });

    it("commercial().pam().access_rules() does not perform any server calls to construct", () => {
      // Constructing the client chain is purely local FFI plumbing - no crypto init and no
      // network access is required to obtain the access rules client itself. Actual CRUD
      // operations (list/add/edit/remove) do call the server and are intentionally out of scope
      // for this harness, which has no mock-server pattern (see `tests/invite/invite-link.test.ts`
      // for the harness's equivalent org-scoped, no-mock-server client tests).
      const client = makeCommercialClient();

      expect(() => client.commercial().pam().access_rules()).not.toThrow();
    });
  });

  describe("is_valid_cidr", () => {
    it.each([
      ["10.0.0.0/8", true],
      ["2001:db8::/32", true],
      ["10.0.0.1/8", false],
      ["10.0.0.0", false],
      ["garbage", false],
    ] as const)("is_valid_cidr(%s) === %s", (value, expected) => {
      expect(is_valid_cidr(value)).toEqual(expected);
    });
  });

  describe("type imports compile", () => {
    // These helpers perform no assertions at runtime - they exist solely so the TypeScript
    // compiler resolves `AccessRuleView`, `AccessCondition`, `AccessRuleAddEditRequest`, and
    // `AccessRuleError` from the generated commercial bindings. Field shapes are intentionally
    // not asserted here since the underlying Rust models (`bitwarden_license/bitwarden-pam/src/
    // access_rules/models.rs`) are still being authored concurrently.
    function identityAccessRuleView(value: AccessRuleView): AccessRuleView {
      return value;
    }

    function identityAccessCondition(value: AccessCondition): AccessCondition {
      return value;
    }

    function identityAccessRuleAddEditRequest(
      value: AccessRuleAddEditRequest,
    ): AccessRuleAddEditRequest {
      return value;
    }

    function identityAccessRuleError(value: AccessRuleError): AccessRuleError {
      return value;
    }

    it("compiles with the access rule types imported from the commercial package", () => {
      expect(typeof identityAccessRuleView).toBe("function");
      expect(typeof identityAccessCondition).toBe("function");
      expect(typeof identityAccessRuleAddEditRequest).toBe("function");
      expect(typeof identityAccessRuleError).toBe("function");
    });
  });
});
