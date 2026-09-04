// Proof that the harness's own mechanisms fire.
//
// Everything here would otherwise fail silently: a secret inspector that never matches, a route
// table that answers a request it should not have, a stale-write check that lets every write
// through, a dump that changes between runs. Each would leave the rest of the suite passing while
// proving nothing, so each is exercised directly.
//
// This is the one file that builds requests by hand. Feature tests assert on stored state instead.

import { asCipherId, asEncString } from "../type-assertion-helpers";

import { ApiServer, type SeedAccount } from "./api-server";
import { KdfType, type CipherRequest, type CipherResponse } from "./dto";
import { installServers, type InstalledServers } from "./install";
import { API_URL, KEY_CONNECTOR_URL } from "./urls";

const PASSWORD = "correct-horse-battery-staple";
const USER_KEY = "dGVzdC11c2VyLWtleS1ub3QtYS1yZWFsLWtleS1hdC1hbGw=";
const PRIVATE_KEY = "2.aGVsbG8=|d29ybGQ=|c2ln";
const MASTER_KEY = "bWFzdGVyLWtleS1ub3QtYS1yZWFsLWtleQ==";

const ACCOUNT: SeedAccount = {
  name: "model-server-account",
  account: {
    userId: "bc010100-0000-4000-8000-000000000000",
    email: "model-server@test.bitwarden.com",
    password: PASSWORD,
    kdf: { pBKDF2: { iterations: 5000 } },
    securityVersion: 1,
    accountCryptographicState: { V1: { private_key: asEncString(PRIVATE_KEY) } },
  },
  unlockMethods: [
    {
      masterPasswordUnlock: {
        password: PASSWORD,
        master_password_unlock: {
          masterKeyWrappedUserKey: asEncString("2.d3JhcHBlZA==|dXNlcmtleQ==|bWFj"),
          salt: "model-server@test.bitwarden.com",
          kdf: { pBKDF2: { iterations: 5000 } },
        },
      },
    },
  ],
  rawCryptographicState: {
    userKey: USER_KEY,
    masterKey: MASTER_KEY,
    privateKey: PRIVATE_KEY,
    publicKey: "cHVibGljLWtleQ==",
  },
};

/** A minimal legacy cipher create body. */
function cipherRequest(overrides: Partial<CipherRequest> = {}): CipherRequest {
  return { type: 1, name: "2.bmFtZQ==|Y2lwaGVy|bWFj", ...overrides };
}

function post(path: string, body: unknown): Promise<Response> {
  return fetch(`${API_URL}${path}`, { method: "POST", body: JSON.stringify(body) });
}

function put(path: string, body: unknown): Promise<Response> {
  return fetch(`${API_URL}${path}`, { method: "PUT", body: JSON.stringify(body) });
}

describe("model server", () => {
  let api: ApiServer;
  let servers: InstalledServers;

  beforeEach(() => {
    api = new ApiServer();
    api.seedUser(ACCOUNT);
    servers = installServers({ api });
  });

  // In `afterEach`, not at the end of each body: a failing assertion would otherwise leave the
  // patched global `fetch` in place for every test that follows.
  afterEach(() => servers.restore());

  describe("secret inspector", () => {
    it.each([
      ["password", PASSWORD],
      ["user key", USER_KEY],
      ["private key", PRIVATE_KEY],
      ["master key", MASTER_KEY],
    ])("catches the account's %s on the wire", async (label, secret) => {
      await post("/ciphers", cipherRequest({ notes: `leaked: ${secret}` }));

      expect(api.secretLeaks()).toEqual([`POST /ciphers: ${label} of ${ACCOUNT.account.email}`]);
    });

    it("stays quiet for a body carrying no secret", async () => {
      await post("/ciphers", cipherRequest());

      expect(api.secretLeaks()).toEqual([]);
    });

    it("catches a secret sent to a route the model does not serve", async () => {
      await post("/nowhere", { leaked: PASSWORD });

      expect(api.secretLeaks()).toEqual([`POST /nowhere: password of ${ACCOUNT.account.email}`]);
    });
  });

  describe("routing", () => {
    it("records a request no route matched and answers 501", async () => {
      const response = await fetch(`${API_URL}/nowhere`);

      expect(response.status).toBe(501);
      expect(servers.unmatched.map((request) => request.route)).toEqual(["GET /nowhere"]);
    });

    it("does not answer for another origin", async () => {
      const response = await fetch(`${KEY_CONNECTOR_URL}/accounts/keys`);

      expect(response.status).toBe(501);
      expect(servers.unmatched.map((request) => request.route)).toEqual(["GET /accounts/keys"]);
    });

    it("captures a path parameter", async () => {
      const created: CipherResponse = await (await post("/ciphers", cipherRequest())).json();

      const response = await put(`/ciphers/${created.id}`, cipherRequest({ favorite: true }));

      expect(response.status).toBe(200);
      expect(api.db.ciphers.get(created.id)?.favorite).toBe(true);
    });

    it("prefers a literal route over a pattern that also matches", async () => {
      const extraRoutes = { "GET /ciphers/all": () => ({ json: { matched: "literal" } }) };
      servers.restore();
      servers = installServers({ api, extraRoutes });

      const response = await fetch(`${API_URL}/ciphers/all`);

      expect(await response.json()).toEqual({ matched: "literal" });
    });
  });

  describe("write semantics", () => {
    it("rejects a write made against a superseded revision", async () => {
      const created: CipherResponse = await (await post("/ciphers", cipherRequest())).json();
      await put(`/ciphers/${created.id}`, cipherRequest({ notes: "2.Zmlyc3Q=|d3JpdGU=|bWFj" }));

      const response = await put(
        `/ciphers/${created.id}`,
        cipherRequest({ lastKnownRevisionDate: created.revisionDate }),
      );

      expect(response.status).toBe(409);
      expect(api.db.ciphers.get(created.id)?.notes).toBe("2.Zmlyc3Q=|d3JpdGU=|bWFj");
    });

    it("accepts a write made against the current revision", async () => {
      const created: CipherResponse = await (await post("/ciphers", cipherRequest())).json();

      const response = await put(
        `/ciphers/${created.id}`,
        cipherRequest({ lastKnownRevisionDate: created.revisionDate, favorite: true }),
      );

      expect(response.status).toBe(200);
      expect(api.db.ciphers.get(created.id)?.favorite).toBe(true);
    });

    it("gives each created item its own id", async () => {
      const first: CipherResponse = await (await post("/ciphers", cipherRequest())).json();
      const second: CipherResponse = await (await post("/ciphers", cipherRequest())).json();

      expect(first.id).not.toBe(second.id);
      expect(api.db.ciphers.all()).toHaveLength(2);
    });

    it("keeps fields the client cannot change across an edit", async () => {
      const created: CipherResponse = await (await post("/ciphers", cipherRequest())).json();
      const stored = api.db.ciphers.get(created.id);
      if (stored === undefined) {
        throw new Error(`the create did not store cipher ${created.id}`);
      }
      api.db.ciphers.update(created.id, { ...stored, organizationUseTotp: false });

      await put(`/ciphers/${created.id}`, cipherRequest({ favorite: true }));

      expect(api.db.ciphers.get(created.id)?.organizationUseTotp).toBe(false);
    });
  });

  describe("dumps", () => {
    it("is byte-stable across two identical runs", async () => {
      const run = async () => {
        const fresh = new ApiServer();
        fresh.seedUser(ACCOUNT);
        const installed = installServers({ api: fresh });
        try {
          await post("/ciphers", cipherRequest());
          await post("/folders", { name: "2.Zm9sZGVy|bmFtZQ==|bWFj" });
          return JSON.stringify(fresh.dump());
        } finally {
          installed.restore();
        }
      };

      servers.restore();
      expect(await run()).toBe(await run());
    });

    it("does not put the account's secrets in the dump", () => {
      const dumped = JSON.stringify(api.dump());

      expect(dumped).not.toContain(PASSWORD);
      expect(dumped).not.toContain(USER_KEY);
    });
  });

  describe("kdf", () => {
    const NEW_KDF = { kdfType: KdfType.argon2id, iterations: 3, memory: 16, parallelism: 4 };

    it("stores the posted unlock data and kdf", async () => {
      const response = await post("/accounts/kdf", {
        masterPasswordHash: "aGFzaA==",
        authenticationData: {
          kdf: NEW_KDF,
          masterPasswordAuthenticationHash: "YXV0aA==",
          salt: "s",
        },
        unlockData: { kdf: NEW_KDF, masterKeyWrappedUserKey: "7.bmV3|d3JhcA==", salt: "s" },
      });

      expect(response.status).toBe(200);
      const stored = api.db.userByEmail(ACCOUNT.account.email);
      expect(stored.kdf).toEqual({ argon2id: { iterations: 3, memory: 16, parallelism: 4 } });
      expect(stored.masterPasswordUnlock).toEqual({
        masterKeyWrappedUserKey: asEncString("7.bmV3|d3JhcA=="),
        salt: "s",
        kdf: { argon2id: { iterations: 3, memory: 16, parallelism: 4 } },
      });
    });

    it("refuses a change that proves no possession of the current password", async () => {
      const response = await post("/accounts/kdf", {
        masterPasswordHash: "",
        authenticationData: {
          kdf: NEW_KDF,
          masterPasswordAuthenticationHash: "YXV0aA==",
          salt: "s",
        },
        unlockData: { kdf: NEW_KDF, masterKeyWrappedUserKey: "7.bmV3|d3JhcA==", salt: "s" },
      });

      expect(response.status).toBe(400);
      expect(api.db.userByEmail(ACCOUNT.account.email).kdf).toEqual({
        pBKDF2: { iterations: 5000 },
      });
    });
  });

  describe("accounts", () => {
    it("serves a V1 account without a signature key pair or security state", async () => {
      const response = await (await fetch(`${API_URL}/accounts/keys`)).json();

      expect(response).toEqual({
        object: "privateKeys",
        publicKeyEncryptionKeyPair: {
          object: "publicKeyEncryptionKeyPair",
          wrappedPrivateKey: PRIVATE_KEY,
          publicKey: "cHVibGljLWtleQ==",
        },
      });
    });

    it("serves the acting account, not whichever was seeded first", async () => {
      const second: SeedAccount = {
        ...ACCOUNT,
        name: "second",
        account: {
          ...ACCOUNT.account,
          userId: "bc010101-0000-4000-8000-000000000000",
          email: "second@test.bitwarden.com",
        },
        rawCryptographicState: { ...ACCOUNT.rawCryptographicState, publicKey: "c2Vjb25k" },
      };
      api.seedUser(second);
      api.actAs("second@test.bitwarden.com");

      const response = await (await fetch(`${API_URL}/accounts/keys`)).json();

      expect(response.publicKeyEncryptionKeyPair.publicKey).toBe("c2Vjb25k");
    });
  });

  describe("sync", () => {
    it("serves only the acting account's vault", async () => {
      api.db.ciphers.set("bc020001-0000-4000-8000-000000000000", "someone-else", {
        ...cipherFixture(),
        id: asCipherId("bc020001-0000-4000-8000-000000000000"),
      });
      await post("/ciphers", cipherRequest());

      const response = await (await fetch(`${API_URL}/sync`)).json();

      expect(response.ciphers).toHaveLength(1);
      expect(response.profile.email).toBe(ACCOUNT.account.email);
    });
  });
});

/** A stored cipher with every required field, for seeding the database directly. */
function cipherFixture() {
  return {
    id: asCipherId("bc020000-0000-4000-8000-000000000000"),
    organizationId: undefined,
    folderId: undefined,
    collectionIds: [],
    key: undefined,
    name: asEncString("2.bmFtZQ==|Y2lwaGVy|bWFj"),
    notes: undefined,
    type: 1 as const,
    login: undefined,
    identity: undefined,
    card: undefined,
    secureNote: undefined,
    sshKey: undefined,
    bankAccount: undefined,
    driversLicense: undefined,
    passport: undefined,
    favorite: false,
    reprompt: 0 as const,
    organizationUseTotp: true,
    edit: true,
    permissions: undefined,
    viewPassword: true,
    localData: undefined,
    attachments: undefined,
    fields: undefined,
    passwordHistory: undefined,
    creationDate: "2025-01-01T00:00:01Z",
    deletedDate: undefined,
    revisionDate: "2025-01-01T00:00:01Z",
    archivedDate: undefined,
    data: undefined,
  };
}
