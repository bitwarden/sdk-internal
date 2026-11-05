// Selecting committed vectors, and running one test body against each.

import type { InitUserCryptoMethod } from "@bitwarden/sdk-internal";

import {
  hasMasterPassword,
  loadEmergencyAccessVectors,
  loadUserVectors,
  unlockMethodName,
  type EmergencyAccessVector,
  type MasterPasswordUserVector,
  type UserVector,
} from "./load";

/**
 * A selection of user vectors. Narrow it with the filters, then pick one or run a test over each.
 *
 * ```ts
 * const V1_VECTOR = testVectors.users.withMasterPassword().get("v1-pbkdf2-min-iterations");
 *
 * testVectors.users
 *   .withMasterPassword()
 *   .except("v1-pbkdf2-password")
 *   .each("$name keeps its user key", async (vector) => {
 *     await rotateAndAssert(vector);
 *   });
 * ```
 */
class UserVectors<V extends UserVector = UserVector> {
  constructor(private readonly vectors: readonly V[]) {}

  /** Only the vectors whose account has a master password. */
  withMasterPassword(): UserVectors<V & MasterPasswordUserVector> {
    return new UserVectors(
      this.vectors.filter((vector): vector is V & MasterPasswordUserVector =>
        hasMasterPassword(vector),
      ),
    );
  }

  /** All but the named vectors. Throws on a name not in the selection, so a typo cannot no-op. */
  except(...names: string[]): UserVectors<V> {
    for (const name of names) {
      // throw if missing
      this.get(name);
    }

    return new UserVectors(this.vectors.filter((vector) => !names.includes(vector.name)));
  }

  /** The named vector. Throws, listing the selection, when it is not in it. */
  get(name: string): V {
    const found = this.vectors.find((vector) => vector.name === name);
    if (found === undefined) {
      const available = this.vectors.map((vector) => vector.name).join(", ");
      throw new Error(`no user vector ${name} in this selection; have ${available}`);
    }

    return found;
  }

  all(): V[] {
    return [...this.vectors];
  }

  /** `it.each` over the selection. `$name` in the title is the vector's name. */
  each(title: string, fn: (vector: V) => Promise<void>, timeout?: number): void {
    it.each(this.all())(title, (vector) => fn(vector), timeout);
  }

  /**
   * `it.each` over every unlock method each selected vector declares. `$name` in the title is the
   * vector's name, `$methodName` the unlock method's variant.
   */
  eachUnlockMethod(
    title: string,
    fn: (vector: V, method: InitUserCryptoMethod) => Promise<void>,
    timeout?: number,
  ): void {
    const rows = this.vectors.flatMap((vector) =>
      vector.unlockMethods.map((method) => ({
        name: vector.name,
        methodName: unlockMethodName(method),
        vector,
        method,
      })),
    );

    it.each(rows)(title, ({ vector, method }) => fn(vector, method), timeout);
  }
}

/**
 * The emergency access vectors.
 *
 * ```ts
 * const vector = testVectors.emergencyAccess.get("v1-grants-v2");
 * ```
 */
class EmergencyAccessVectors {
  constructor(private readonly vectors: readonly EmergencyAccessVector[]) {}

  /** The named vector. Throws, listing the selection, when it is not in it. */
  get(name: string): EmergencyAccessVector {
    const found = this.vectors.find((vector) => vector.name === name);
    if (found === undefined) {
      const available = this.vectors.map((vector) => vector.name).join(", ");
      throw new Error(`no emergency access vector ${name}; have ${available}`);
    }

    return found;
  }

  all(): EmergencyAccessVector[] {
    return [...this.vectors];
  }

  /** `it.each` over the selection. `$name` in the title is the vector's name. */
  each(
    title: string,
    fn: (vector: EmergencyAccessVector) => Promise<void>,
    timeout?: number,
  ): void {
    it.each(this.all())(title, (vector) => fn(vector), timeout);
  }
}

export const testVectors = {
  users: new UserVectors(loadUserVectors()),
  emergencyAccess: new EmergencyAccessVectors(loadEmergencyAccessVectors()),
};
