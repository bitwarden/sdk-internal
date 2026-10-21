import { Cipher, CipherView } from "@bitwarden/sdk-internal";

import { encstring, makeInitializedPasswordmanagerClient, makeStateBridge } from "../utils";

/**
 * An `EncString` whose iv decodes to 4 bytes instead of the required 16. It is well-formed base64
 * in the right shape, so it only fails the length check.
 */
const MALFORMED_IV = "2.AAECAw==|Y3Q=|AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

const cipherView = (name: string): CipherView =>
  ({
    id: undefined,
    organizationId: undefined,
    folderId: undefined,
    collectionIds: [],
    key: undefined,
    name,
    notes: undefined,
    type: 1,
    login: {
      username: undefined,
      password: undefined,
      passwordRevisionDate: undefined,
      uris: undefined,
      totp: undefined,
      autofillOnPageLoad: undefined,
      fido2Credentials: undefined,
    },
    identity: undefined,
    card: undefined,
    secureNote: undefined,
    sshKey: undefined,
    bankAccount: undefined,
    driversLicense: undefined,
    passport: undefined,
    favorite: false,
    reprompt: 0,
    organizationUseTotp: false,
    edit: true,
    permissions: undefined,
    viewPassword: true,
    localData: undefined,
    attachments: undefined,
    fields: undefined,
    passwordHistory: undefined,
    creationDate: "2024-01-01T00:00:00Z",
    deletedDate: undefined,
    revisionDate: "2024-01-01T00:00:00Z",
    archivedDate: undefined,
  }) as unknown as CipherView;

// A malformed `EncString` used to throw while being lifted across the boundary, before the called
// method ran. It now crosses as an unparseable `EncString`, so a single bad item is reported as a
// per-item decryption failure instead of taking down the whole call.
describe("CiphersClient.decrypt_list_full_with_failures with an unparseable EncString", () => {
  const setup = async () => {
    const client = await makeInitializedPasswordmanagerClient(makeStateBridge());
    const ciphers = client.vault().ciphers();
    const { cipher: valid } = await ciphers.encrypt(cipherView("valid"));

    // The item key protects every field, so an unparseable one fails the whole cipher.
    const malformed: Cipher = { ...valid, key: encstring(MALFORMED_IV) };
    return { ciphers, valid, malformed };
  };

  it("reports the malformed cipher as a failure and still decrypts the rest", async () => {
    const { ciphers, valid, malformed } = await setup();

    const result = await ciphers.decrypt_list_full_with_failures([valid, malformed]);

    expect(result.successes.map((c) => c.name)).toEqual(["valid"]);
    expect(result.failures.length).toBe(1);
    // The raw value survives the round trip, so the caller can report or re-send it unchanged.
    expect(result.failures[0].key).toBe(MALFORMED_IV);
  });

  it("reports every cipher as a failure when they are all malformed", async () => {
    const { ciphers, malformed } = await setup();

    const result = await ciphers.decrypt_list_full_with_failures([malformed, malformed]);

    expect(result.successes).toEqual([]);
    expect(result.failures.length).toBe(2);
  });
});
