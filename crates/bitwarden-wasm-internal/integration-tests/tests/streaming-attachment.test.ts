import {
  PureCrypto,
  SymmetricKey,
  decrypt_attachment_stream,
  encrypt_attachment_stream,
  init_sdk,
} from "@bitwarden/sdk-internal";

beforeAll(() => {
  init_sdk();
});

function makeKey(): SymmetricKey {
  return Buffer.from(PureCrypto.make_user_key_aes256_cbc_hmac()).toString(
    "base64",
  ) as unknown as SymmetricKey;
}

function bytesToStream(bytes: Uint8Array): ReadableStream<Uint8Array> {
  // Must be a byte stream (type: "bytes") because the Rust side uses
  // ReadableStream::into_async_read(), which requires BYOB. Real callers
  // (fetch Response.body, File.stream()) are byte streams already.
  return new ReadableStream({
    type: "bytes",
    start(controller) {
      // Copy into a fresh ArrayBuffer-backed view so the controller's
      // typing (which wants ArrayBufferView<ArrayBuffer>, not the more
      // permissive ArrayBufferLike) is satisfied.
      if (bytes.length > 0) {
        const copy = new Uint8Array(new ArrayBuffer(bytes.length));
        copy.set(bytes);
        controller.enqueue(copy);
      }
      controller.close();
    },
  } as UnderlyingByteSource);
}

async function streamToBytes(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) {
      break;
    }
    chunks.push(value);
    total += value.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

async function roundtrip(key: SymmetricKey, plaintext: Uint8Array): Promise<Uint8Array> {
  const wire = await streamToBytes(encrypt_attachment_stream(key, bytesToStream(plaintext)));
  return streamToBytes(decrypt_attachment_stream(key, bytesToStream(wire)));
}

describe("streaming attachment cipher (WASM)", () => {
  it("roundtrips a short plaintext", async () => {
    const key = makeKey();
    const plaintext = new TextEncoder().encode(
      "streaming attachment cipher: WASM roundtrip test plaintext.",
    );
    const decrypted = await roundtrip(key, plaintext);
    expect(Buffer.from(decrypted)).toEqual(Buffer.from(plaintext));
  });

  it("roundtrips a 1 MiB plaintext across many cipher blocks", async () => {
    const key = makeKey();
    const plaintext = new Uint8Array(1024 * 1024);
    for (let i = 0; i < plaintext.length; i++) {
      plaintext[i] = i % 251;
    }
    const decrypted = await roundtrip(key, plaintext);
    expect(decrypted.length).toBe(plaintext.length);
    expect(Buffer.from(decrypted)).toEqual(Buffer.from(plaintext));
  });

  it("roundtrips an empty plaintext", async () => {
    const key = makeKey();
    const decrypted = await roundtrip(key, new Uint8Array(0));
    expect(decrypted.length).toBe(0);
  });

  it("emits the AES-CBC-HMAC discriminator as the first wire byte", async () => {
    const key = makeKey();
    const plaintext = new TextEncoder().encode("hello");
    const wire = await streamToBytes(encrypt_attachment_stream(key, bytesToStream(plaintext)));
    expect(wire[0]).toBe(0x02);
  });

  it("rejects a tampered ciphertext", async () => {
    const key = makeKey();
    const plaintext = new TextEncoder().encode(
      "streaming attachment cipher: tampered ciphertext should fail.",
    );
    const wire = await streamToBytes(encrypt_attachment_stream(key, bytesToStream(plaintext)));
    // Flip a byte in the middle of the AES-CBC ciphertext body (past discriminator + IV + HMAC).
    const tamperOffset = 1 + 16 + 32 + 4;
    wire[tamperOffset] ^= 0xff;

    await expect(
      streamToBytes(decrypt_attachment_stream(key, bytesToStream(wire))),
    ).rejects.toBeDefined();
  });

  it("fails to decrypt with the wrong key", async () => {
    const encryptKey = makeKey();
    const decryptKey = makeKey();
    const plaintext = new TextEncoder().encode("wrong-key test plaintext");
    const wire = await streamToBytes(
      encrypt_attachment_stream(encryptKey, bytesToStream(plaintext)),
    );

    await expect(
      streamToBytes(decrypt_attachment_stream(decryptKey, bytesToStream(wire))),
    ).rejects.toBeDefined();
  });
});
