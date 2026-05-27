import { randomBytes } from "node:crypto";

import {
  PureCrypto,
  WasmAttachmentDecryptor,
  WasmAttachmentEncryptor,
} from "@bitwarden/sdk-internal";

function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function encryptInChunks(key: Uint8Array, plaintext: Uint8Array, chunkSize: number): Uint8Array {
  const enc = new WasmAttachmentEncryptor(key);
  const out: Uint8Array[] = [];
  for (let i = 0; i < plaintext.length; i += chunkSize) {
    out.push(enc.update(plaintext.subarray(i, i + chunkSize)));
  }
  out.push(enc.finalize());
  return concat(out);
}

function decryptInChunks(key: Uint8Array, wire: Uint8Array, chunkSize: number): Uint8Array {
  const dec = new WasmAttachmentDecryptor(key);
  const out: Uint8Array[] = [];
  for (let i = 0; i < wire.length; i += chunkSize) {
    out.push(dec.update(wire.subarray(i, i + chunkSize)));
  }
  out.push(dec.finalize());
  return concat(out);
}

describe("WasmAttachmentEncryptor / WasmAttachmentDecryptor", () => {
  it("round-trips a small plaintext", () => {
    const key = PureCrypto.make_user_key_aes256_cbc_hmac();
    const plaintext = new TextEncoder().encode("hello attachment");

    const wire = encryptInChunks(key, plaintext, 7);
    expect(wire[0]).toBe(0x02); // AES-CBC-HMAC discriminator

    const decrypted = decryptInChunks(key, wire, 5);
    expect(decrypted).toEqual(plaintext);
  });

  it("round-trips a multi-KB plaintext across many chunks", () => {
    const key = PureCrypto.make_user_key_aes256_cbc_hmac();
    const plaintext = new Uint8Array(randomBytes(32 * 1024 + 137));

    const wire = encryptInChunks(key, plaintext, 4096);
    const decrypted = decryptInChunks(key, wire, 1024);

    expect(decrypted).toEqual(plaintext);
  });

  it("handles single-byte chunks (exercises discriminator hand-off)", () => {
    const key = PureCrypto.make_user_key_aes256_cbc_hmac();
    const plaintext = new TextEncoder().encode("chunk by chunk");

    const wire = encryptInChunks(key, plaintext, 1);
    const decrypted = decryptInChunks(key, wire, 1);

    expect(decrypted).toEqual(plaintext);
  });

  it("rejects decryption with the wrong key", () => {
    const encKey = PureCrypto.make_user_key_aes256_cbc_hmac();
    const wrongKey = PureCrypto.make_user_key_aes256_cbc_hmac();
    const plaintext = new TextEncoder().encode("secret payload");

    const wire = encryptInChunks(encKey, plaintext, 32);

    expect(() => decryptInChunks(wrongKey, wire, 32)).toThrow();
  });

  it("rejects a wire stream with an unknown discriminator", () => {
    const key = PureCrypto.make_user_key_aes256_cbc_hmac();
    const wire = encryptInChunks(key, new TextEncoder().encode("payload"), 32);
    wire[0] = 0x07; // not 0x02

    const dec = new WasmAttachmentDecryptor(key);
    expect(() => dec.update(wire)).toThrow();
  });

  it("rejects a truncated wire stream", () => {
    const key = PureCrypto.make_user_key_aes256_cbc_hmac();
    const wire = encryptInChunks(key, new TextEncoder().encode("payload data"), 32);
    const truncated = wire.subarray(0, wire.length - 16);

    expect(() => decryptInChunks(key, truncated, 32)).toThrow();
  });
});
