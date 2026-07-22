import { makePasswordManagerClient, makeStateBridge } from "../utils";

const SAMPLE_INPUT = {
  organization_id: "1bc9ac1e-f5aa-45f2-94bf-b181009709b8",
  invite_link_code: "abcd1234efgh5678",
  invite_key: "raw-invite-key-material-base64url",
};

describe("open org invite registration seal/unseal", () => {
  it("seal_open_org_invite_data returns a non-empty sealed_data and paired high_entropy_secret", async () => {
    const client = makePasswordManagerClient(makeStateBridge());

    const sealed = client.auth().registration().seal_open_org_invite_data(SAMPLE_INPUT);

    expect(sealed.sealed_data).not.toEqual("");
    expect(sealed.high_entropy_secret).not.toEqual("");
  });

  it("unseal_open_org_invite_data recovers the plaintext invite context with fields intact", async () => {
    const client = makePasswordManagerClient(makeStateBridge());
    const registration = client.auth().registration();

    const sealed = await registration.seal_open_org_invite_data(SAMPLE_INPUT);
    const unsealed = await registration.unseal_open_org_invite_data(sealed);

    expect(unsealed.organization_id).toEqual(SAMPLE_INPUT.organization_id);
    expect(unsealed.invite_link_code).toEqual(SAMPLE_INPUT.invite_link_code);
    expect(unsealed.invite_key).toEqual(SAMPLE_INPUT.invite_key);
  });

  it("two independent seals produce different high_entropy_secret values (per-registration randomness)", async () => {
    const client = makePasswordManagerClient(makeStateBridge());
    const registration = client.auth().registration();

    const first = await registration.seal_open_org_invite_data(SAMPLE_INPUT);
    const second = await registration.seal_open_org_invite_data(SAMPLE_INPUT);

    expect(first.high_entropy_secret).not.toEqual(second.high_entropy_secret);
    expect(first.sealed_data).not.toEqual(second.sealed_data);
  });

  it("the sealed_data serializes as base64url that crosses the FFI boundary intact", async () => {
    const client = makePasswordManagerClient(makeStateBridge());

    const sealed = client.auth().registration().seal_open_org_invite_data(SAMPLE_INPUT);

    // sealed_data is base64url-encoded CBOR; must round-trip through base64url decode + re-encode.
    // Base64url uses `-` and `_` instead of `+` and `/`, and omits `=` padding — Node's Buffer
    // does not have a native "base64url" encoding, so translate via Buffer("base64") after
    // reversing the URL-safe substitutions.
    const sealedStr = sealed.sealed_data as unknown as string;
    expect(sealedStr).not.toEqual("");
    const b64 = sealedStr.replace(/-/g, "+").replace(/_/g, "/");
    // Pad back to a multiple of 4 for Buffer.from("base64").
    const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    const reencoded = Buffer.from(padded, "base64")
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    expect(reencoded).toEqual(sealedStr);
  });
});
