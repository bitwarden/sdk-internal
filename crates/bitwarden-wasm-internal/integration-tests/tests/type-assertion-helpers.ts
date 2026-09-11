import type {
  B64,
  CipherId,
  CollectionId,
  EncString,
  FolderId,
  KeyId,
  OrganizationId,
  PublicKey,
  SendId,
  UnsignedSharedKey,
  UserId,
  Uuid,
} from "@bitwarden/sdk-internal";

const typeAssert = <T>(value: string): T => value as unknown as T;

export const asCipherId = (value: string): CipherId => typeAssert(value);
export const asFolderId = (value: string): FolderId => typeAssert(value);
export const asSendId = (value: string): SendId => typeAssert(value);
export const asUserId = (value: string): UserId => typeAssert(value);
export const asCollectionId = (value: string): CollectionId => typeAssert(value);
export const asOrganizationId = (value: string): OrganizationId => typeAssert(value);
export const asKeyId = (value: string): KeyId => typeAssert(value);
export const asEncString = (value: string): EncString => typeAssert(value);
export const asB64 = (value: string): B64 => typeAssert(value);
export const asPublicKey = (value: string): PublicKey => typeAssert(value);
export const asUnsignedSharedKey = (value: string): UnsignedSharedKey => typeAssert(value);
export const asUuid = (value: string): string => typeAssert(value);
export const fromUuid = (value: Uuid): string => typeAssert(value as unknown as string);
export const asString = (value: string | { toString(): string }): string => String(value);
