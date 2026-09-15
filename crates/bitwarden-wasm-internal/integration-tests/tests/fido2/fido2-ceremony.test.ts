// Runs real CTAP ceremonies through the WASM bridge: make_credential, then get_assertion over
// the credential that produced.
//
// Unlike fido2-bridge.test.ts, which only checks that callbacks arrive, this exercises the
// FIDO2 logic end to end. The credential round-trips through encryption: `save_credential`
// receives an `EncryptionContext` and stores the encrypted cipher, and `find_credentials`
// decrypts it again, so nothing is passed back as the same in-memory object.

import {
  Cipher,
  CipherId,
  CipherRepromptType,
  CipherType,
  CipherView,
  EncryptionContext,
  Fido2CredentialStore,
  Fido2UserInterface,
  GetAssertionRequest,
  MakeCredentialRequest,
  PasswordManagerClient,
} from "@bitwarden/sdk-internal";

import { makeInitializedPasswordmanagerClient, makeStateBridge } from "../utils";

const RP_ID = "bitwarden.com";
const USER_HANDLE = [1, 2, 3, 4];
const CLIENT_DATA_HASH = Array.from({ length: 32 }, (_, i) => i);
/** ES256, the only algorithm the authenticator supports. */
const ES256 = -7;

const cipherId = (s: string) => s as unknown as CipherId;

/** An empty login cipher, standing in for the one a user would pick during registration. */
function blankLoginCipher(): CipherView {
  const now = new Date().toISOString() as unknown as CipherView["creationDate"];
  return {
    id: cipherId("00000000-0000-0000-0000-000000000001"),
    organizationId: undefined,
    folderId: undefined,
    collectionIds: [],
    key: undefined,
    name: "bitwarden.com passkey",
    notes: undefined,
    type: CipherType.Login,
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
    reprompt: CipherRepromptType.None,
    organizationUseTotp: false,
    edit: true,
    permissions: undefined,
    viewPassword: true,
    localData: undefined,
    attachments: undefined,
    fields: undefined,
    passwordHistory: undefined,
    creationDate: now,
    deletedDate: undefined,
    revisionDate: now,
    archivedDate: undefined,
  };
}

/**
 * A credential store backed by the client's own encryption, so credentials survive the same
 * encrypt/decrypt trip they would in a real vault.
 */
function makeVaultStore(client: PasswordManagerClient) {
  const ciphers = client.vault().ciphers();
  const saved: Cipher[] = [];
  /** Argument shapes observed at the boundary, asserted on below. */
  const observed: { ids: unknown; userHandle: unknown }[] = [];

  const store: Fido2CredentialStore = {
    find_credentials: async (ids, rip_id, user_handle) => {
      observed.push({ ids, userHandle: user_handle });
      const views = await Promise.all(saved.map((c) => ciphers.decrypt(c)));
      return views.filter((view) =>
        // `rpId` is only readable once the credential is decrypted: the `fido2Credentials` on a
        // CipherView are still the encrypted type.
        ciphers.decrypt_fido2_credentials(view).some((cred) => cred.rpId === rip_id),
      );
    },
    all_credentials: async () => ciphers.decrypt_list(saved),
    save_credential: async (cred: EncryptionContext) => {
      saved.push(cred.cipher);
    },
  };

  return { store, saved, observed };
}

/** A user interface that approves everything, as a user who taps through the prompts would. */
function makeApprovingUserInterface() {
  const calls: string[] = [];
  const ui = {
    check_user: async () => {
      calls.push("check_user");
      return { userPresent: true, userVerified: true };
    },
    pick_credential_for_authentication: async (available: CipherView[]) => {
      calls.push("pick_credential_for_authentication");
      return available[0];
    },
    check_user_and_pick_credential_for_creation: async () => {
      calls.push("check_user_and_pick_credential_for_creation");
      return {
        cipher: blankLoginCipher(),
        checkUserResult: { userPresent: true, userVerified: true },
      };
    },
    is_verification_enabled: true,
  } as unknown as Fido2UserInterface;

  return { ui, calls };
}

function makeCredentialRequest(): MakeCredentialRequest {
  return {
    clientDataHash: CLIENT_DATA_HASH,
    rp: { id: RP_ID, name: "Bitwarden" },
    user: { id: USER_HANDLE, name: "user@bitwarden.com", displayName: "Test User" },
    pubKeyCredParams: [{ ty: "public-key", alg: ES256 }],
    excludeList: undefined,
    // `rk: true` makes the credential discoverable, which is what lets get_assertion and
    // silently_discover_credentials find it afterwards.
    options: { rk: true, uv: "discouraged" },
    extensions: undefined,
  };
}

function getAssertionRequest(credentialId: number[]): GetAssertionRequest {
  return {
    rpId: RP_ID,
    clientDataHash: CLIENT_DATA_HASH,
    allowList: [{ ty: "public-key", id: credentialId, transports: undefined }],
    options: { rk: true, uv: "discouraged" },
    extensions: undefined,
  };
}

describe("fido2 ceremony", () => {
  let client: PasswordManagerClient;

  beforeEach(async () => {
    client = await makeInitializedPasswordmanagerClient(makeStateBridge());
  });

  it("creates a credential and persists it through save_credential", async () => {
    const { store, saved } = makeVaultStore(client);
    const { ui, calls } = makeApprovingUserInterface();
    const authenticator = client.platform().fido2().authenticator(ui, store);

    const result = await authenticator.make_credential(makeCredentialRequest());

    expect(calls).toContain("check_user_and_pick_credential_for_creation");
    expect(result.credentialId.length).toBeGreaterThan(0);
    expect(result.attestationObject.length).toBeGreaterThan(0);
    expect(saved).toHaveLength(1);
  });

  it("asserts the credential it just created", async () => {
    const { store } = makeVaultStore(client);
    const { ui } = makeApprovingUserInterface();
    const fido2 = client.platform().fido2();

    const created = await fido2.authenticator(ui, store).make_credential(makeCredentialRequest());
    // A fresh authenticator, as a second ceremony would use.
    const assertion = await fido2
      .authenticator(makeApprovingUserInterface().ui, store)
      .get_assertion(getAssertionRequest(created.credentialId));

    expect(assertion.credentialId).toEqual(created.credentialId);
    expect(assertion.signature.length).toBeGreaterThan(0);
    expect(assertion.userHandle).toEqual(USER_HANDLE);
    expect(assertion.selectedCredential.credential.rpId).toBe(RP_ID);
  });

  it("hands find_credentials plain arrays, not Uint8Array", async () => {
    const { store, observed } = makeVaultStore(client);
    const { ui } = makeApprovingUserInterface();
    const fido2 = client.platform().fido2();

    const created = await fido2.authenticator(ui, store).make_credential(makeCredentialRequest());
    await fido2
      .authenticator(makeApprovingUserInterface().ui, store)
      .get_assertion(getAssertionRequest(created.credentialId));

    // The interface declares `number[][]` and `number[]` because serde_wasm_bindgen does not
    // emit Uint8Array for a plain Vec<u8>. This is that claim, checked.
    const withIds = observed.filter((o) => o.ids !== undefined);
    expect(withIds.length).toBeGreaterThan(0);
    for (const { ids } of withIds) {
      expect(Array.isArray(ids)).toBe(true);
      for (const id of ids as unknown[]) {
        expect(Array.isArray(id)).toBe(true);
        expect(id).not.toBeInstanceOf(Uint8Array);
      }
    }
  });

  it("discovers the credential silently, with no user interaction", async () => {
    const { store } = makeVaultStore(client);
    const { ui } = makeApprovingUserInterface();
    const fido2 = client.platform().fido2();

    await fido2.authenticator(ui, store).make_credential(makeCredentialRequest());
    const silent = makeApprovingUserInterface();
    const discovered = await fido2
      .authenticator(silent.ui, store)
      .silently_discover_credentials(RP_ID);

    expect(discovered).toHaveLength(1);
    expect(discovered[0].rpId).toBe(RP_ID);
    expect(silent.calls).toEqual([]);
  });
});
