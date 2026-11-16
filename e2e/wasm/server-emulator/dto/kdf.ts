// The server's KDF settings, as its request and response models carry them.

import type { Kdf } from "@bitwarden/sdk-internal";

/** The server's numeric `KdfType`. */
export const KdfType = { pbkdf2Sha256: 0, argon2id: 1 } as const;
export type KdfTypeValue = (typeof KdfType)[keyof typeof KdfType];

export class KdfModel {
  kdfType!: KdfTypeValue;
  iterations!: number;
  memory?: number;
  parallelism?: number;

  static fromKdf(kdf: Kdf): KdfModel {
    if ("pBKDF2" in kdf) {
      return { kdfType: KdfType.pbkdf2Sha256, iterations: kdf.pBKDF2.iterations };
    } else {
      return {
        kdfType: KdfType.argon2id,
        iterations: kdf.argon2id.iterations,
        memory: kdf.argon2id.memory,
        parallelism: kdf.argon2id.parallelism,
      };
    }
  }
}

export function toKdf(kdf: KdfModel): Kdf {
  if (kdf.kdfType === KdfType.pbkdf2Sha256) {
    return { pBKDF2: { iterations: kdf.iterations } };
  }

  if (kdf.kdfType === KdfType.argon2id) {
    if (kdf.memory === undefined || kdf.parallelism === undefined) {
      throw new Error(`argon2id kdf without memory or parallelism: ${JSON.stringify(kdf)}`);
    }

    return {
      argon2id: { iterations: kdf.iterations, memory: kdf.memory, parallelism: kdf.parallelism },
    };
  }

  throw new Error(`unrecognised kdf: ${JSON.stringify(kdf)}`);
}
