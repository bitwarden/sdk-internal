// An in-memory model of the server's seeder API (`util/SeederApi`): accounts written straight to
// the database under a play id, and destroyed by it. A test environment may run one; production
// never does.

import { randomBytes } from "node:crypto";

import { PureCrypto, type Kdf } from "@bitwarden/sdk-internal";

import { asAccountId, asEncString } from "../tests/type-assertion-helpers";
import { masterPasswordAuthenticationHash } from "../tests/utils";

import type { Database } from "./database";
import type { UserEntity } from "./entities";
import type { MockReply, MockRequest, Routes } from "./http-mock";
import type { IdentityServer } from "./identity-server";
import { HTTP_BAD_REQUEST, HTTP_NOT_FOUND, HTTP_UNAUTHORIZED } from "./replies";

/** The seeder's default PBKDF2 iterations: low, for speed. */
const DEFAULT_KDF_ITERATIONS = 5_000;

const BASIC_PREFIX = "Basic ";

/** What `SingleUserScene` takes. */
interface SingleUserSceneArguments {
  email?: string;
  password?: string;
  kdfIterations?: number;
}

interface SeedRequest {
  template: string;
  arguments?: SingleUserSceneArguments;
}

export class SeederServer {
  constructor(
    private readonly db: Database,
    private readonly identity: IdentityServer,
  ) {}

  routes(): Routes {
    return {
      "POST /seed": (request) => authorized(request, () => this.seed(request)),

      "DELETE /seed/:playId": (request) =>
        authorized(request, () => this.destroy(request.params.playId)),
    };
  }

  /**
   * Runs a scene, recording what it writes under the request's play id. Only `SingleUserScene` is
   * modelled; any other answers as an unknown scene does.
   */
  private seed(request: MockRequest): MockReply {
    const posted = request.json<SeedRequest>();
    if (posted.template !== "SingleUserScene") {
      return refusal(HTTP_NOT_FOUND, `scene ${posted.template} not found`);
    }

    const { email, password, kdfIterations } = posted.arguments ?? {};
    if (!email || !password) {
      return refusal(HTTP_BAD_REQUEST, "SingleUserScene needs an email and a password");
    }
    if (this.identity.userFor(email) !== undefined) {
      return refusal(HTTP_BAD_REQUEST, `email ${email} is already taken`);
    }

    // Stored under a mangled address, as a seeder that tracks play ids stores every seeded one.
    const mangled = mangle(email);
    const user = seededUser(this.db.users.newId(), mangled, password, {
      pBKDF2: { iterations: kdfIterations ?? DEFAULT_KDF_ITERATIONS },
    });
    this.db.users.set(user.userId, user);

    const playId = request.headers.get("X-Play-Id");
    if (playId) {
      this.db.playItems.set(playId, [...(this.db.playItems.get(playId) ?? []), user.userId]);
    }

    // The real seeder also answers with the account's keys, its decrypted user key among them. The
    // emulator answers with the id and KDF only, so nothing in the suite can come to depend on them.
    return {
      json: {
        mangleMap: { [email]: mangled },
        result: {
          userId: user.userId,
          kdf: "PBKDF2_SHA256",
          kdfIterations: kdfIterations ?? DEFAULT_KDF_ITERATIONS,
        },
      },
    };
  }

  /** Destroys every account seeded under `playId`. One with no record is a no-op, as on the server. */
  private destroy(playId: string): MockReply {
    for (const userId of this.db.playItems.get(playId) ?? []) {
      this.db.removeUser(userId);
    }
    this.db.playItems.remove(playId);

    return { json: {} };
  }
}

/** An address with the seeder's random prefix: `1854b016+name@example.com`. */
function mangle(email: string): string {
  return `${randomBytes(4).toString("hex")}+${email}`;
}

/**
 * An account as the seeder writes one: keys made server-side, and only their Protected Data
 * stored. A V1 account, salted with its address, with a PBKDF2 KDF.
 */
function seededUser(userId: string, email: string, password: string, kdf: Kdf): UserEntity {
  const userKey = PureCrypto.make_user_key_aes256_cbc_hmac();
  const privateKey = PureCrypto.rsa_generate_keypair();
  const publicKey = Buffer.from(PureCrypto.rsa_extract_public_key(privateKey)).toString("base64");

  return {
    userId: asAccountId(userId),
    email,
    accountCryptographicState: {
      V1: { private_key: asEncString(PureCrypto.wrap_decapsulation_key(privateKey, userKey)) },
    },
    publicKey,
    verifyingKey: null,
    kdf,
    masterPasswordUnlock: {
      masterKeyWrappedUserKey: asEncString(
        PureCrypto.encrypt_user_key_with_master_password(userKey, password, email, kdf),
      ),
      salt: email,
      kdf,
    },
    masterPasswordAuthenticationHash: masterPasswordAuthenticationHash(password, email, kdf),
    organizationKeys: {},
  };
}

/** The seeder takes basic authentication; the emulator checks that some was sent. */
function authorized(request: MockRequest, handle: () => MockReply): MockReply {
  if (!request.headers.get("Authorization")?.startsWith(BASIC_PREFIX)) {
    return { status: HTTP_UNAUTHORIZED };
  }

  return handle();
}

/** A refusal, in the seeder's shape. */
function refusal(status: number, message: string): MockReply {
  return { status, json: { error: message } };
}
