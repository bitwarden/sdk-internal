import { makePasswordManagerClient, makeStateBridge } from "../utils";

const SAMPLE_INPUT = {
  organizationId: "1bc9ac1e-f5aa-45f2-94bf-b181009709b8",
  inviteLinkCode: "abcd1234efgh5678",
  inviteKey: "raw-invite-key-material-base64url",
};

describe("open org invite registration seal/unseal", () => {
  it("seal_open_org_invite_data returns a non-empty sealedData and paired highEntropySecret", async () => {
    const client = makePasswordManagerClient(makeStateBridge());

    const sealed = client.auth().registration().seal_open_org_invite_data(SAMPLE_INPUT);

    expect(sealed.sealedData).not.toEqual("");
    expect(sealed.highEntropySecret).not.toEqual("");
  });

  it("unseal_open_org_invite_data recovers the plaintext invite context with fields intact", () => {
    const client = makePasswordManagerClient(makeStateBridge());
    const registration = client.auth().registration();

    const sealed = registration.seal_open_org_invite_data(SAMPLE_INPUT);
    const unsealed = registration.unseal_open_org_invite_data(sealed);

    expect(unsealed.organizationId).toEqual(SAMPLE_INPUT.organizationId);
    expect(unsealed.inviteLinkCode).toEqual(SAMPLE_INPUT.inviteLinkCode);
    expect(unsealed.inviteKey).toEqual(SAMPLE_INPUT.inviteKey);
  });

  it("two independent seals produce different highEntropySecret values (per-registration randomness)", () => {
    const client = makePasswordManagerClient(makeStateBridge());
    const registration = client.auth().registration();

    const first = registration.seal_open_org_invite_data(SAMPLE_INPUT);
    const second = registration.seal_open_org_invite_data(SAMPLE_INPUT);

    expect(first.highEntropySecret).not.toEqual(second.highEntropySecret);
    expect(first.sealedData).not.toEqual(second.sealedData);
  });

  it("the sealedData serializes as base64url that crosses the FFI boundary intact", async () => {
    const client = makePasswordManagerClient(makeStateBridge());

    const sealed = client.auth().registration().seal_open_org_invite_data(SAMPLE_INPUT);

    // Wire-format sanity: sealedData must round-trip through Node's native "base64url"
    // encoding (available since Node 16) without drift.
    const sealedStr = sealed.sealedData as unknown as string;
    expect(sealedStr).not.toEqual("");
    const reencoded = Buffer.from(sealedStr, "base64url").toString("base64url");
    expect(reencoded).toEqual(sealedStr);
  });
});
