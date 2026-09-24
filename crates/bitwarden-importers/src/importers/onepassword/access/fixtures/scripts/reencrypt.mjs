#!/usr/bin/env node
// Re-keys a captured 1Password fixture from the account's real credentials to made-up ones.
//
// The master keyset is the only thing sealed with the password-derived key. Every other key
// hangs off its symmetric key, which stays the same, so vault keys and items need no change.
// The envelope keeps its IV and the file keeps its formatting, so the diff is the re-sealed
// `data` plus the fields that name the account's owner.
//
//   node scripts/reencrypt.mjs keysets --old-email … --old-password … --old-secret-key … account/keysets-response.json
//   node scripts/reencrypt.mjs account --old-email … --old-password … --old-secret-key … account/account-response.json
//
// The `--new-*` options default to the credentials replay.rs uses.

import { createCipheriv, createDecipheriv, hkdfSync, pbkdf2Sync } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import prettier from "prettier";

const TEST_CREDENTIALS = {
  email: "user@example.com",
  password: "password",
  secretKey: "A3-ABCDEF-GHJKLM-NPQRS-TVWXY-Z2345-6789A",
};
const TEST_NAME = { firstName: "Example", lastName: "User", name: "Example User" };
const TEST_INVITE_SECRET = "ABCDEFGHJKLMNPQRSTVWXYZ234";

// The slice of 1Password's crypto this needs, mirroring account_key.rs, kdf.rs and opdata.rs.

// Base32 without the confusable characters. The web client drops everything else from the input.
const SECRET_KEY_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTVWXYZ";
const SECRET_KEY_LENGTH = 34;
const KEY_LENGTH = 32;
const TAG_LENGTH = 16;

function parseSecretKey(input) {
  const key = [...input.toUpperCase()].filter((c) => SECRET_KEY_ALPHABET.includes(c)).join("");
  if (!key.startsWith("A3") || key.length !== SECRET_KEY_LENGTH) {
    throw new Error(
      `invalid Secret Key: expected A3 and ${SECRET_KEY_LENGTH} characters, got ${key.length}`,
    );
  }
  return { format: key.slice(0, 2), uuid: key.slice(2, 8), key: key.slice(8) };
}

function hkdf(info, ikm, salt) {
  return Buffer.from(hkdfSync("sha256", ikm, salt, info, KEY_LENGTH));
}

// The master unlock key, kid "mp". Modern prefix only: no capture uses the legacy one.
function deriveMasterKey({ email, password, secretKey }, { alg, p2s, p2c }) {
  if (alg !== "PBES2g-HS256") {
    throw new Error(`unsupported key derivation: ${alg}`);
  }
  const username = email.trim().toLowerCase();
  const salt = hkdf(alg, Buffer.from(p2s, "base64url"), Buffer.from(username));
  const derived = pbkdf2Sync(password.trim().normalize("NFKD"), salt, p2c, KEY_LENGTH, "sha256");
  const { format, uuid, key } = parseSecretKey(secretKey);
  const hashed = hkdf(format, Buffer.from(key), Buffer.from(uuid));
  return hashed.map((byte, i) => byte ^ derived[i]);
}

// Decrypts an envelope's `data`, which is `ciphertext || tag` in base64url.
function openEnvelope(key, { enc, iv, data }) {
  if (enc !== "A256GCM") {
    throw new Error(`unsupported encryption scheme: ${enc}`);
  }
  const bytes = Buffer.from(data, "base64url");
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "base64url"));
  decipher.setAuthTag(bytes.subarray(-TAG_LENGTH));
  const plaintext = decipher.update(bytes.subarray(0, -TAG_LENGTH));
  try {
    return Buffer.concat([plaintext, decipher.final()]);
  } catch {
    throw new Error("the key does not open the envelope");
  }
}

// The inverse: `plaintext` sealed under `key` with the envelope's own IV.
function sealEnvelope(key, { iv }, plaintext) {
  const cipher = createCipheriv("aes-256-gcm", key, Buffer.from(iv, "base64url"));
  const sealed = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  return sealed.toString("base64url");
}

// Reseals every master keyset's symmetric key. The newest master keyset carries the KDF
// parameters, and the key derived from them opens every one, as in keychain.rs.
function rekeyMasterKeysets(keysets, oldCredentials, newCredentials) {
  const masters = keysets.filter((keyset) => keyset.encryptedBy === "mp");
  if (masters.length === 0) {
    throw new Error("no master keyset");
  }
  const newest = masters.reduce((a, b) => (b.sn > a.sn ? b : a)).encSymKey;
  const oldMasterKey = deriveMasterKey(oldCredentials, newest);
  const newMasterKey = deriveMasterKey(newCredentials, newest);
  for (const { encSymKey } of masters) {
    const symmetricKey = openEnvelope(oldMasterKey, encSymKey);
    encSymKey.data = sealEnvelope(newMasterKey, encSymKey, symmetricKey);
  }
}

// `v1/account/keysets`.
function reencryptKeysets(json, oldCredentials, newCredentials) {
  if (!Array.isArray(json.keysets)) {
    throw new Error("not a keysets response");
  }
  rekeyMasterKeysets(json.keysets, oldCredentials, newCredentials);
}

// `v1/account`: the embedded master keyset plus everything that names the account's owner.
function reencryptAccount(json, oldCredentials, newCredentials) {
  const { me } = json;
  if (!Array.isArray(me?.keysets)) {
    throw new Error("not an account response");
  }
  rekeyMasterKeysets(me.keysets, oldCredentials, newCredentials);

  // An individual account is named after its owner.
  if (json.name === me.name) {
    json.name = TEST_NAME.name;
  }
  for (const user of [me, ...json.users.filter((user) => user.uuid === me.uuid)]) {
    Object.assign(user, { email: newCredentials.email, ...TEST_NAME });
  }
  const { format, uuid } = parseSecretKey(newCredentials.secretKey);
  me.accountKeyFormat = format;
  me.accountKeyUuid = uuid;
  json.invite.inviteSecret = TEST_INVITE_SECRET;
}

const FIXTURES = { keysets: reencryptKeysets, account: reencryptAccount };

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    "old-email": { type: "string" },
    "old-password": { type: "string" },
    "old-secret-key": { type: "string" },
    "new-email": { type: "string", default: TEST_CREDENTIALS.email },
    "new-password": { type: "string", default: TEST_CREDENTIALS.password },
    "new-secret-key": { type: "string", default: TEST_CREDENTIALS.secretKey },
  },
});
const credentials = (age) => ({
  email: values[`${age}-email`],
  password: values[`${age}-password`],
  secretKey: values[`${age}-secret-key`],
});

const [kind, file] = positionals;
const reencrypt = FIXTURES[kind];
const old = credentials("old");
if (!reencrypt || !file || !old.email || !old.password || !old.secretKey) {
  console.error(
    `usage: reencrypt.mjs <${Object.keys(FIXTURES).join("|")}> --old-email … --old-password …` +
      " --old-secret-key … [--new-email …] [--new-password …] [--new-secret-key …] <fixture.json>",
  );
  process.exit(2);
}

const json = JSON.parse(readFileSync(file, "utf8"));
reencrypt(json, old, credentials("new"));
// The captures are prettier formatted, so reformatting keeps the diff to the changed values.
const options = { ...(await prettier.resolveConfig(file)), parser: "json" };
writeFileSync(file, await prettier.format(JSON.stringify(json, null, 2), options));
