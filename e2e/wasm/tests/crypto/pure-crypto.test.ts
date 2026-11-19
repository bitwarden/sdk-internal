import { PureCrypto } from "@bitwarden/sdk-internal";

// `SymmetricKey` is exposed across the FFI as a base64-encoded `Tagged<string>`.
const decode = (key: unknown): Buffer => Buffer.from(key as unknown as string, "base64");

describe("PureCrypto.make_aes256_cbc_hmac_key", () => {
  it("generates a 64-byte AES256-CBC-HMAC key", () => {
    const key = PureCrypto.make_aes256_cbc_hmac_key();

    // AES256-CBC-HMAC keys are 64 bytes: a 32-byte encryption key + a 32-byte MAC key.
    expect(decode(key).length).toBe(64);
  });

  it("produces a distinct key on each call", () => {
    const first = PureCrypto.make_aes256_cbc_hmac_key();
    const second = PureCrypto.make_aes256_cbc_hmac_key();

    // Two independently generated keys are overwhelmingly unlikely to collide.
    expect(decode(first).equals(decode(second))).toBe(false);
  });
});
