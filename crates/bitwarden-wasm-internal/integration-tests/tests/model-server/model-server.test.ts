// Self-checks for the model server itself.
//
// Every other suite leans on four mechanisms of this harness, and all four fail *silently* if they
// break: an unmatched route would stop being noticed, the two origins would stop being distinct, the
// secret inspector would stop policing anything, and revision conflicts would stop being rejected. A
// no-op guard is worse than no guard, because it reads as coverage. So the guards are guarded here.
//
// This is also the one file allowed to construct request bodies by hand. Everywhere else, tests assert
// on the account the server holds and on whether it can be unlocked again — never on what the client
// posted.

import { loadUserVectors, userVector } from "../test-vectors/load";

import { ApiServer } from "./api-server";
import { LocalState } from "./local-state";
import { syncToLocalState, unlockMethodFor } from "./sync";
import { API_URL, installServers, KEY_CONNECTOR_URL } from "./install";
import { KeyConnectorServer } from "./key-connector-server";

const users = loadUserVectors();
/** The cheapest vector in the set to unlock: PBKDF2 at 5,000 rounds. */
const vector = userVector(users, "v1-pbkdf2-min-iterations");

function seeded() {
  const api = new ApiServer();
  api.seedUser(vector);
  return api;
}

describe("secret inspector", () => {
  it.each([
    ["master password", () => vector.account.password],
    ["user key", () => vector.rawCryptographicState.userKey],
    ["private key", () => vector.rawCryptographicState.privateKey],
  ])("catches the %s reaching the wire", async (label, secret) => {
    const api = seeded();
    const servers = installServers({ api });
    expect(api.secretLeaks()).toEqual([]);

    await fetch(`${API_URL}/ciphers`, {
      method: "POST",
      body: JSON.stringify({ leaked: secret() }),
    });

    expect(api.secretLeaks()).toEqual([`POST /ciphers: ${label}`]);
    servers.restore();
  });

  it("stays quiet for a body carrying no secrets", async () => {
    const api = seeded();
    const servers = installServers({ api });

    await fetch(`${API_URL}/ciphers`, {
      method: "POST",
      body: JSON.stringify({ name: "2.abc|def|ghi", type: 1 }),
    });

    expect(api.secretLeaks()).toEqual([]);
    servers.restore();
  });

  it("watches the key connector's origin too, not just the API's", async () => {
    const api = seeded();
    const servers = installServers({ api, keyConnector: new KeyConnectorServer() });

    await fetch(`${KEY_CONNECTOR_URL}/user-keys`, {
      method: "POST",
      body: JSON.stringify({ key: vector.rawCryptographicState.userKey }),
    });

    expect(api.secretLeaks()).toEqual(["POST /user-keys: user key"]);
    servers.restore();
  });
});

describe("routing", () => {
  it("records an unmodelled route as unmatched", async () => {
    const api = seeded();
    const servers = installServers({ api });

    await fetch(`${API_URL}/not/a/real/endpoint`);

    expect(servers.unmatched.map((r) => r.route)).toEqual(["GET /not/a/real/endpoint"]);
    servers.restore();
  });

  it("keeps the two origins distinct", async () => {
    // Before origins were part of the route key, the key connector answered `/user-keys` no matter
    // which host the request went to.
    const api = seeded();
    const keyConnector = new KeyConnectorServer();
    keyConnector.seedKey("AAAA");
    const servers = installServers({ api, keyConnector });

    expect((await fetch(`${API_URL}/user-keys`)).status).toBe(501);
    expect(servers.unmatched.map((r) => r.route)).toEqual(["GET /user-keys"]);

    expect((await fetch(`${KEY_CONNECTOR_URL}/user-keys`)).status).toBe(200);
    expect(servers.unmatched).toHaveLength(1);
    servers.restore();
  });
});

describe("key connector", () => {
  // The connector has no upsert, which is the whole reason a client reads before it writes. Enforcing
  // that here means no test has to inspect which route was called to find out which verb was chosen —
  // a client that picks wrong simply fails.
  it("refuses a create when a key already exists", async () => {
    const api = seeded();
    const keyConnector = new KeyConnectorServer();
    keyConnector.seedKey("AAAA");
    const servers = installServers({ api, keyConnector });

    const created = await fetch(`${KEY_CONNECTOR_URL}/user-keys`, {
      method: "POST",
      body: JSON.stringify({ key: "BBBB" }),
    });

    expect(created.status).toBe(409);
    expect(keyConnector.key()).toBe("AAAA");
    servers.restore();
  });

  it("refuses an update when no key exists", async () => {
    const api = seeded();
    const keyConnector = new KeyConnectorServer();
    const servers = installServers({ api, keyConnector });

    const updated = await fetch(`${KEY_CONNECTOR_URL}/user-keys`, {
      method: "PUT",
      body: JSON.stringify({ key: "BBBB" }),
    });

    expect(updated.status).toBe(404);
    expect(keyConnector.key()).toBeUndefined();
    servers.restore();
  });
});

describe("write semantics", () => {
  it("rejects a write built on a stale revision, and accepts a current one", async () => {
    const api = seeded();
    const servers = installServers({ api });
    const item = vector.vault.ciphers[0];
    const stored: any = api.db.ciphers.get(item.id)!.cipher;

    const stale = await fetch(`${API_URL}/ciphers/${item.id}`, {
      method: "PUT",
      body: JSON.stringify({ ...stored, lastKnownRevisionDate: "2000-01-01T00:00:00Z" }),
    });
    expect(stale.status).toBe(409);

    const current = await fetch(`${API_URL}/ciphers/${item.id}`, {
      method: "PUT",
      body: JSON.stringify({ ...stored, lastKnownRevisionDate: stored.revisionDate }),
    });
    expect(current.status).toBe(200);
    servers.restore();
  });

  it("produces a byte-stable dump for the same sequence of operations", async () => {
    // Revisions come from a counter rather than the clock, so two identical runs must dump
    // identically. A wall-clock server would differ here, and every dump comparison would rot.
    const run = async () => {
      const api = seeded();
      const servers = installServers({ api });
      const local = new LocalState();
      await syncToLocalState(api, vector.account.email, local);
      const client = await local.unlock(unlockMethodFor(api, vector.account.email));
      await client
        .vault()
        .ciphers()
        .soft_delete(vector.vault.ciphers[0].id as never);
      const dump = JSON.stringify(api.dump());
      servers.restore();
      return dump;
    };

    expect(await run()).toBe(await run());
  }, 120_000);
});
