// Converts plain strings into the SDK's id and ciphertext types.

import type {
  B64,
  CipherId,
  EncString,
  FolderId,
  OrganizationId,
  UnsignedSharedKey,
  UserId,
} from "@bitwarden/sdk-internal";

export const asCipherId = (id: string): CipherId => id as unknown as CipherId;
export const asFolderId = (id: string): FolderId => id as unknown as FolderId;
export const asUserId = (id: string): UserId => id as unknown as UserId;
export const asOrganizationId = (id: string): OrganizationId => id as unknown as OrganizationId;
export const asEncString = (value: string): EncString => value as unknown as EncString;
export const asB64 = (value: string): B64 => value as unknown as B64;
export const asUnsignedSharedKey = (value: string): UnsignedSharedKey =>
  value as unknown as UnsignedSharedKey;
