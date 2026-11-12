// Master-password authentication and unlock data, as the server's models carry them.

import { asEncString } from "../../tests/type-assertion-helpers";
import type { StoredMasterPasswordUnlock } from "../entities";
import { KdfModel, toKdf } from "./kdf";

export class MasterPasswordAuthenticationDataModel {
  kdf!: KdfModel;
  masterPasswordAuthenticationHash!: string;
  salt!: string;
}

export class MasterPasswordUnlockDataModel {
  kdf!: KdfModel;
  masterKeyWrappedUserKey!: string;
  salt!: string;
  containedKeyId?: string;

  static toStored(posted: MasterPasswordUnlockDataModel): StoredMasterPasswordUnlock {
    return {
      masterKeyWrappedUserKey: asEncString(posted.masterKeyWrappedUserKey),
      salt: posted.salt,
      kdf: toKdf(posted.kdf),
      containedKeyId: posted.containedKeyId,
    };
  }
}

/**
 * `MasterPasswordUnlockResponseModel`.
 */
export class MasterPasswordUnlockResponse {
  kdf!: KdfModel;
  masterKeyEncryptedUserKey!: string;
  salt!: string;
  containedKeyId!: string | null;

  static fromStored(unlock: StoredMasterPasswordUnlock): MasterPasswordUnlockResponse {
    return {
      kdf: KdfModel.fromKdf(unlock.kdf),
      masterKeyEncryptedUserKey: unlock.masterKeyWrappedUserKey,
      salt: unlock.salt,
      containedKeyId: unlock.containedKeyId ?? null,
    };
  }
}
