import { OrganizationId } from "@bitwarden/sdk-internal";

import { TEST_ORGANIZATION_ID } from "./org-fixtures";
import { makeOrgInitializedClient, makeStateBridge } from "./utils";

const UNKNOWN_ORGANIZATION_ID = "ffffffff-ffff-4fff-8fff-ffffffffffff" as unknown as OrganizationId;

describe("invite link client tests", () => {
  it("make_invite returns a non-empty invite key and sealed invite", async () => {
    const client = await makeOrgInitializedClient(makeStateBridge());

    const bundle = client.invite_link().make_invite(TEST_ORGANIZATION_ID);

    expect(bundle.inviteKey as unknown as string).not.toEqual("");
    expect(bundle.invite as unknown as string).not.toEqual("");
  });

  it("get_invite_key unseals the sealed invite back to the raw invite key", async () => {
    const client = await makeOrgInitializedClient(makeStateBridge());

    const inviteLink = client.invite_link();
    const bundle = inviteLink.make_invite(TEST_ORGANIZATION_ID);
    const unsealed = inviteLink.get_invite_key(TEST_ORGANIZATION_ID, bundle.invite);

    expect(unsealed as unknown as string).toEqual(bundle.inviteKey as unknown as string);
  });

  it("two calls produce different invite keys", async () => {
    const client = await makeOrgInitializedClient(makeStateBridge());

    const inviteLink = client.invite_link();
    const first = inviteLink.make_invite(TEST_ORGANIZATION_ID);
    const second = inviteLink.make_invite(TEST_ORGANIZATION_ID);

    expect(first.inviteKey as unknown as string).not.toEqual(second.inviteKey as unknown as string);
  });

  it("the sealed invite serializes as a base64 wire format that crosses the FFI boundary intact", async () => {
    const client = await makeOrgInitializedClient(makeStateBridge());

    const bundle = client.invite_link().make_invite(TEST_ORGANIZATION_ID);

    // The invite is serialized as a base64-encoded CBOR structure (the
    // extendable wire format), so it must be valid, round-trippable base64.
    const inviteStr = bundle.invite as unknown as string;
    expect(inviteStr).not.toEqual("");
    expect(Buffer.from(inviteStr, "base64").toString("base64")).toEqual(inviteStr);
  });

  it("make_invite fails for an organization that is not in the key store", async () => {
    const client = await makeOrgInitializedClient(makeStateBridge());

    expect(() => client.invite_link().make_invite(UNKNOWN_ORGANIZATION_ID)).toThrow();
  });

  it("get_invite_key fails when unsealing with the wrong organization", async () => {
    const client = await makeOrgInitializedClient(makeStateBridge());

    const inviteLink = client.invite_link();
    const bundle = inviteLink.make_invite(TEST_ORGANIZATION_ID);

    expect(() => inviteLink.get_invite_key(UNKNOWN_ORGANIZATION_ID, bundle.invite)).toThrow();
  });
});
