import { OrganizationId } from "@bitwarden/sdk-internal";

import { ORG_WRAPPED_PRIVATE_KEY, TEST_ORGANIZATION_ID } from "../org-fixtures";
import { makeOrgInitializedClient, makeStateBridge } from "../utils";

const UNKNOWN_ORGANIZATION_ID = "ffffffff-ffff-4fff-8fff-ffffffffffff" as unknown as OrganizationId;

describe("invite link client tests", () => {
  it("make_invite returns a non-empty invite secret and invite", async () => {
    const client = await makeOrgInitializedClient(makeStateBridge());

    const bundle = client.invite_link().make_invite(TEST_ORGANIZATION_ID, ORG_WRAPPED_PRIVATE_KEY);

    expect(bundle.inviteSecret as unknown as string).not.toEqual("");
    expect(bundle.invite as unknown as string).not.toEqual("");
  });

  it("get_invite_secret unseals the invite back to the raw invite secret", async () => {
    const client = await makeOrgInitializedClient(makeStateBridge());

    const inviteLink = client.invite_link();
    const bundle = inviteLink.make_invite(TEST_ORGANIZATION_ID, ORG_WRAPPED_PRIVATE_KEY);
    const unsealed = inviteLink.get_invite_secret(TEST_ORGANIZATION_ID, bundle.invite);

    expect(unsealed as unknown as string).toEqual(bundle.inviteSecret as unknown as string);
  });

  it("two calls produce different invite secrets", async () => {
    const client = await makeOrgInitializedClient(makeStateBridge());

    const inviteLink = client.invite_link();
    const first = inviteLink.make_invite(TEST_ORGANIZATION_ID, ORG_WRAPPED_PRIVATE_KEY);
    const second = inviteLink.make_invite(TEST_ORGANIZATION_ID, ORG_WRAPPED_PRIVATE_KEY);

    expect(first.inviteSecret as unknown as string).not.toEqual(
      second.inviteSecret as unknown as string,
    );
  });

  it("the invite serializes as a base64 wire format that crosses the FFI boundary intact", async () => {
    const client = await makeOrgInitializedClient(makeStateBridge());

    const bundle = client.invite_link().make_invite(TEST_ORGANIZATION_ID, ORG_WRAPPED_PRIVATE_KEY);

    // The invite is serialized as a base64-encoded CBOR structure (the
    // extendable wire format), so it must be valid, round-trippable base64.
    const inviteStr = bundle.invite as unknown as string;
    expect(inviteStr).not.toEqual("");
    expect(Buffer.from(inviteStr, "base64").toString("base64")).toEqual(inviteStr);
  });

  it("make_invite fails for an organization that is not in the key store", async () => {
    const client = await makeOrgInitializedClient(makeStateBridge());

    expect(() =>
      client.invite_link().make_invite(UNKNOWN_ORGANIZATION_ID, ORG_WRAPPED_PRIVATE_KEY),
    ).toThrow();
  });

  it("get_invite_secret fails when unsealing with the wrong organization", async () => {
    const client = await makeOrgInitializedClient(makeStateBridge());

    const inviteLink = client.invite_link();
    const bundle = inviteLink.make_invite(TEST_ORGANIZATION_ID, ORG_WRAPPED_PRIVATE_KEY);

    expect(() => inviteLink.get_invite_secret(UNKNOWN_ORGANIZATION_ID, bundle.invite)).toThrow();
  });
});
