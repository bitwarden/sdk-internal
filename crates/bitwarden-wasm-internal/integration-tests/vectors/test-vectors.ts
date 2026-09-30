// Running one test body against every account the committed vectors record.

import { loadUserVectors, unlockCases, vectorCases } from "./load";

export const testVectors = {
  /**
   * `it.each` over every known user vector, called with the vector's name and the vector itself.
   *
   * ```ts
   * testVectors.eachUser()("%s keeps its user key", async (_name, vector) => {
   *   await rotateAndAssert(vector);
   * });
   * ```
   */
  eachUser() {
    return it.each(vectorCases(loadUserVectors()));
  },

  /**
   * `it.each` over every unlock method every known user vector declares, called with the vector's
   * name, the method's variant name, the vector and the method.
   *
   * ```ts
   * testVectors.eachUserAndUnlockMethod()(
   *   "%s decrypts its vault after unlocking via %s",
   *   async (_name, _methodName, vector, method) => {
   *     await validateVector(vector, method);
   *   },
   * );
   * ```
   */
  eachUserAndUnlockMethod() {
    return it.each(unlockCases(loadUserVectors()));
  },
};
