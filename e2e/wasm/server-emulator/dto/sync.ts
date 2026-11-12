// `GET /sync`'s response and the models only it serves.

import type { Cipher, Folder, ProfileOrganization } from "@bitwarden/sdk-internal";
import {
  OrganizationUserStatusType,
  OrganizationUserType,
  ProductTierType,
} from "@bitwarden/sdk-internal";

import { asKeyId, asOrganizationId, asUserId } from "../../tests/type-assertion-helpers";
import type { OrganizationEntity, OrganizationMember, UserEntity } from "../entities";
import { AccountKeysResponse } from "./account-keys";
import { MasterPasswordUnlockResponse } from "./master-password";
import { CipherResponse, FolderResponse } from "./vault";

/** `V2UpgradeTokenResponseModel`. */
export class V2UpgradeTokenResponse {
  wrappedUserKey1!: string;
  wrappedUserKey2!: string;
}

/**
 * `UserDecryptionResponseModel` — how an account can be unlocked, as `GET /sync` reports it.
 *
 * `webAuthnPrfOptions` is omitted until an account vector has any.
 */
export class UserDecryptionResponse {
  /** `null` for an account without a master password. */
  masterPasswordUnlock!: MasterPasswordUnlockResponse | null;
  /** Omitted, not `null`, when absent, as is {@link userKeyId}. */
  v2UpgradeToken?: V2UpgradeTokenResponse;
  userKeyId?: string;

  static fromUser(user: UserEntity): UserDecryptionResponse {
    return {
      masterPasswordUnlock:
        user.masterPasswordUnlock === null
          ? null
          : MasterPasswordUnlockResponse.fromStored(user.masterPasswordUnlock),
      ...(user.upgradeToken === undefined
        ? {}
        : {
            v2UpgradeToken: {
              wrappedUserKey1: String(user.upgradeToken.wrapped_user_key_1),
              wrappedUserKey2: String(user.upgradeToken.wrapped_user_key_2),
            },
          }),
      userKeyId: user.userKeyId ?? undefined,
    };
  }
}

export class KeysResponse {
  object!: "keys";
  key!: string | null;
  publicKey!: string;
  privateKey!: string;
  accountKeys!: AccountKeysResponse;

  static fromUser(user: UserEntity): KeysResponse {
    return {
      object: "keys",
      key:
        user.masterPasswordUnlock === null
          ? null
          : String(user.masterPasswordUnlock.masterKeyWrappedUserKey),
      publicKey: user.publicKey,
      privateKey: AccountKeysResponse.wrappedPrivateKeyOf(user),
      accountKeys: AccountKeysResponse.fromUser(user),
    };
  }
}

/** The subset of `ProfileResponseModel` the SDK reads. */
/**
 * `ProfileOrganizationResponseModel` — one organization the account is a member of.
 *
 * `key` is the organization key sealed to the account's public key, which is the only way a client
 * ever learns it: a member unseals it at unlock and initializes organization crypto from it.
 */
export class ProfileOrganizationResponse {
  object!: "profileOrganization";
  id!: string;
  name!: string;
  key!: string;
  type!: OrganizationUserType;
  status!: OrganizationUserStatusType;
  enabled!: boolean;
  /** The id of the organization key, or `null` before a member has recorded it. */
  organizationKeyId!: string | null;

  /** The organization as `member` sees it. */
  static fromMembership(
    organization: OrganizationEntity,
    member: OrganizationMember,
  ): ProfileOrganizationResponse {
    return {
      object: "profileOrganization",
      id: organization.organizationId,
      name: organization.name,
      key: member.organizationKeySealedToMember,
      type: member.type,
      status: OrganizationUserStatusType.Confirmed,
      enabled: true,
      organizationKeyId: organization.organizationKeyId,
    };
  }

  /**
   * An organization a vector records only as a key sealed to the account. With no organization
   * row, it reads as one the account is a confirmed `User` of, with no key id recorded.
   */
  static fromSealedKey(id: string, key: string): ProfileOrganizationResponse {
    return {
      object: "profileOrganization",
      id,
      name: "",
      key,
      type: OrganizationUserType.User,
      status: OrganizationUserStatusType.Confirmed,
      enabled: true,
      organizationKeyId: null,
    };
  }

  /**
   * A served organization as a client stores it, as `OrganizationRecordMapper.toSdk` does in the
   * clients. The fields the server emulator does not model take their SDK defaults.
   */
  static toProfileOrganization(
    response: ProfileOrganizationResponse,
    userId: string,
  ): ProfileOrganization {
    return {
      details: {
        id: asOrganizationId(response.id),
        name: response.name,
        enabled: response.enabled,
        hasPublicAndPrivateKeys: false,
        keyId:
          response.organizationKeyId === null ? undefined : asKeyId(response.organizationKeyId),
      },
      plan: {
        productTierType: ProductTierType.Free,
        seats: 10,
        maxCollections: undefined,
        maxStorageGb: undefined,
        selfHost: false,
        usersGetPremium: false,
        usePolicies: false,
        useGroups: false,
        useDirectory: false,
        useEvents: false,
        useTotp: false,
        use2fa: false,
        useApi: false,
        useSso: false,
        useOrganizationDomains: false,
        useKeyConnector: false,
        useScim: false,
        useCustomPermissions: false,
        useResetPassword: false,
        useSecretsManager: false,
        usePasswordManager: false,
        usePam: false,
        useActivateAutofillPolicy: false,
        useAutomaticUserConfirmation: false,
        useAccessIntelligence: false,
        useAdminSponsoredFamilies: false,
        useDisableSMAdsForUsers: false,
        usePhishingBlocker: false,
        useMyItems: false,
        useInviteLinks: false,
      },
      membership: {
        status: response.status,
        type: response.type,
        permissions: {
          accessEventLogs: false,
          accessImportExport: false,
          accessReports: false,
          createNewCollections: false,
          editAnyCollection: false,
          deleteAnyCollection: false,
          manageGroups: false,
          manageSso: false,
          managePolicies: false,
          manageUsers: false,
          manageResetPassword: false,
          manageScim: false,
          manageAccessRules: false,
          manageRotation: false,
        },
        userId: asUserId(userId),
        organizationUserId: undefined,
        isMember: true,
        isProviderUser: false,
        resetPasswordEnrolled: false,
        ssoBound: false,
        userIsClaimedByOrganization: false,
        accessSecretsManager: false,
        accessPam: false,
      },
      collectionManagement: {
        limitCollectionCreation: false,
        limitCollectionDeletion: false,
        limitItemDeletion: false,
        allowAdminAccessToAllCollectionItems: false,
      },
      provider: undefined,
      sso: {
        enabled: false,
        identifier: undefined,
        memberDecryptionType: undefined,
        keyConnectorEnabled: false,
        keyConnectorUrl: undefined,
      },
      familySponsorship: {
        available: false,
        friendlyName: undefined,
        validUntil: undefined,
        lastSyncDate: undefined,
        toDelete: undefined,
        isAdminInitiated: false,
      },
    };
  }
}

export class ProfileResponse {
  object!: "profile";
  id!: string;
  email!: string;
  key!: string | null;
  privateKey!: string | null;
  securityStamp!: string | null;
  organizations!: ProfileOrganizationResponse[];
  /** The account's cryptographic state, which a rotation reads the current keys from. */
  accountKeys!: AccountKeysResponse;

  static fromUser(user: UserEntity, organizations: ProfileOrganizationResponse[]): ProfileResponse {
    return {
      object: "profile",
      id: user.userId,
      email: user.email,
      key: user.masterPasswordUnlock?.masterKeyWrappedUserKey ?? null,
      privateKey: AccountKeysResponse.wrappedPrivateKeyOf(user),
      securityStamp: null,
      organizations,
      accountKeys: AccountKeysResponse.fromUser(user),
    };
  }
}

export class SyncResponse {
  object!: "sync";
  profile!: ProfileResponse;
  userDecryption!: UserDecryptionResponse;
  folders!: FolderResponse[];
  collections!: [];
  ciphers!: CipherResponse[];
  domains!: null;
  policies!: [];
  sends!: [];

  /** `GET /sync` for one account, over the vault the caller can reach. */
  static forUser(
    user: UserEntity,
    vault: { ciphers: Cipher[]; folders: Folder[] },
    organizations: ProfileOrganizationResponse[],
  ): SyncResponse {
    return {
      object: "sync",
      profile: ProfileResponse.fromUser(user, organizations),
      userDecryption: UserDecryptionResponse.fromUser(user),
      folders: vault.folders.map(FolderResponse.fromFolder),
      collections: [],
      ciphers: vault.ciphers.map(CipherResponse.fromCipher),
      domains: null,
      policies: [],
      sends: [],
    };
  }
}
