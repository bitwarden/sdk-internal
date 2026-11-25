// Emergency access grants, as the server takes and serves them.

import type { UnsignedSharedKey } from "@bitwarden/sdk-internal";

import type { EmergencyAccessEntity, StoredMasterPasswordUnlock, UserEntity } from "../entities";
import { KdfModel, type KdfTypeValue } from "./kdf";
import {
  MasterPasswordAuthenticationDataModel,
  MasterPasswordUnlockDataModel,
} from "./master-password";
import { CipherResponse } from "./vault";

/** The server's numeric `EmergencyAccessType`. */
export const EmergencyAccessType = { view: 0, takeover: 1 } as const;
export type EmergencyAccessTypeValue =
  (typeof EmergencyAccessType)[keyof typeof EmergencyAccessType];

/** The server's numeric `EmergencyAccessStatusType`. */
export const EmergencyAccessStatus = {
  invited: 0,
  accepted: 1,
  confirmed: 2,
  recoveryInitiated: 3,
  recoveryApproved: 4,
} as const;
export type EmergencyAccessStatusValue =
  (typeof EmergencyAccessStatus)[keyof typeof EmergencyAccessStatus];

/** `EmergencyAccessGranteeDetailsResponseModel` — what the grantor sees of a grantee. */
export class EmergencyAccessGranteeDetailsResponse {
  object!: "emergencyAccessGranteeDetails";
  id!: string;
  status!: number;
  type!: number;
  waitTimeDays!: number;
  granteeId!: string | null;
  name!: string | null;
  email!: string;
  avatarColor!: string | null;

  /** Before the invite is accepted there is no grantee account, only the address invited. */
  static fromEntity(
    entity: EmergencyAccessEntity,
    grantee: UserEntity | undefined,
  ): EmergencyAccessGranteeDetailsResponse {
    return {
      object: "emergencyAccessGranteeDetails",
      id: entity.id,
      status: entity.status,
      type: entity.type,
      waitTimeDays: entity.waitTimeDays,
      granteeId: entity.granteeId,
      name: null,
      email: grantee?.email ?? entity.email,
      avatarColor: null,
    };
  }
}

/** `EmergencyAccessGrantorDetailsResponseModel` — what the grantee sees of a grantor. */
export class EmergencyAccessGrantorDetailsResponse {
  object!: "emergencyAccessGrantorDetails";
  id!: string;
  status!: number;
  type!: number;
  waitTimeDays!: number;
  grantorId!: string;
  name!: string | null;
  email!: string;
  avatarColor!: string | null;

  static fromEntity(
    entity: EmergencyAccessEntity,
    grantor: UserEntity,
  ): EmergencyAccessGrantorDetailsResponse {
    return {
      object: "emergencyAccessGrantorDetails",
      id: entity.id,
      status: entity.status,
      type: entity.type,
      waitTimeDays: entity.waitTimeDays,
      grantorId: entity.grantorId,
      name: null,
      email: grantor.email,
      avatarColor: null,
    };
  }
}

/** `EmergencyAccessInviteRequestModel`. */
export class EmergencyAccessInviteRequest {
  email!: string;
  type!: EmergencyAccessTypeValue;
  waitTimeDays!: number;
}

/** `EmergencyAccessUpdateRequestModel`. */
export class EmergencyAccessUpdateRequest {
  type!: EmergencyAccessTypeValue;
  waitTimeDays!: number;
  keyEncrypted?: string | null;
}

/** `OrganizationUserAcceptRequestModel`, which the accept route reuses. */
export class EmergencyAccessAcceptRequest {
  token!: string;
}

/** `OrganizationUserConfirmRequestModel`, which the confirm route reuses. */
export class EmergencyAccessConfirmRequest {
  key!: UnsignedSharedKey;
}

/** `EmergencyAccessViewResponseModel`. */
export class EmergencyAccessViewResponse {
  object!: "emergencyAccessView";
  keyEncrypted!: string;
  ciphers!: CipherResponse[];
}

/** `EmergencyAccessTakeoverResponseModel`. */
export class EmergencyAccessTakeoverResponse {
  object!: "emergencyAccessTakeover";
  keyEncrypted!: string;
  kdf!: KdfTypeValue;
  kdfIterations!: number;
  kdfMemory?: number;
  kdfParallelism?: number;
  salt!: string;

  static from(
    keyEncrypted: string,
    unlock: StoredMasterPasswordUnlock,
  ): EmergencyAccessTakeoverResponse {
    const kdf = KdfModel.fromKdf(unlock.kdf);

    return {
      object: "emergencyAccessTakeover",
      keyEncrypted,
      kdf: kdf.kdfType,
      kdfIterations: kdf.iterations,
      kdfMemory: kdf.memory,
      kdfParallelism: kdf.parallelism,
      salt: unlock.salt,
    };
  }
}

/** `EmergencyAccessPasswordRequestModel`. */
export class EmergencyAccessPasswordRequest {
  newMasterPasswordHash?: string | null;
  key?: string | null;
  unlockData?: MasterPasswordUnlockDataModel | null;
  authenticationData?: MasterPasswordAuthenticationDataModel | null;
}
