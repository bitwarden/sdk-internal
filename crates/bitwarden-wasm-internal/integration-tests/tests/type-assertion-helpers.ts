// Conversions from plain strings into the SDK's opaque brands.
//
// Ids and ciphertexts are `Tagged<Uuid, "CipherId">` and friends — deliberately not string subtypes,
// so a plain string cannot be assigned to one. Tests and the model server are banned from casting
// inline; every conversion goes through a named function here, so the whole set is greppable and the
// unavoidable cast lives in exactly one expression.

import type {
  B64,
  CipherId,
  EncString,
  FolderId,
  KeyId,
  OrganizationId,
  PublicKey,
  SendId,
  UnsignedSharedKey,
  UserId,
} from "@bitwarden/sdk-internal";

/** The one cast. Nothing outside this file may widen through `unknown`. */
const brand = <T>(value: string): T => value as unknown as T;

export const asCipherId = (value: string): CipherId => brand(value);
export const asFolderId = (value: string): FolderId => brand(value);
export const asSendId = (value: string): SendId => brand(value);
export const asUserId = (value: string): UserId => brand(value);
export const asOrganizationId = (value: string): OrganizationId => brand(value);
export const asKeyId = (value: string): KeyId => brand(value);
export const asEncString = (value: string): EncString => brand(value);
export const asB64 = (value: string): B64 => brand(value);
export const asPublicKey = (value: string): PublicKey => brand(value);
export const asUnsignedSharedKey = (value: string): UnsignedSharedKey => brand(value);

/**
 * A branded id or ciphertext back to the plain string it is at runtime.
 *
 * The SDK's brands are opaque rather than string intersections, so widening needs a cast even though
 * nothing changes. Serializers use this on the way out to the wire.
 */
export const asString = (value: string | { toString(): string }): string => String(value);
