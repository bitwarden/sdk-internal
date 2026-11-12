// An account's cryptographic keys, as the server takes and serves them.

import type { WrappedAccountCryptographicState } from "@bitwarden/sdk-internal";

import {
  asEncString,
  asSignedPublicKey,
  asSignedSecurityState,
} from "../../tests/type-assertion-helpers";
import type { UserEntity } from "../entities";

/** `PublicKeyEncryptionKeyPairRequestModel`, as a rotation posts it. */
export class PublicKeyEncryptionKeyPairRequest {
  wrappedPrivateKey!: string;
  publicKey!: string;
  signedPublicKey?: string;
}

/** `SignatureKeyPairRequestModel`. */
export class SignatureKeyPairRequest {
  signatureAlgorithm!: number;
  wrappedSigningKey!: string;
  verifyingKey!: string;
}

/** `SecurityStateModel`. */
export class SecurityStateRequest {
  securityState!: string;
  securityVersion!: number;
}

/**
 * `WrappedAccountCryptographicStateRequestModel` — always the V2 shape.
 */
export class WrappedAccountCryptographicStateRequest {
  publicKeyEncryptionKeyPair!: PublicKeyEncryptionKeyPairRequest;
  signatureKeyPair!: SignatureKeyPairRequest;
  securityState!: SecurityStateRequest;
}

export class PublicKeyEncryptionKeyPairResponse {
  object!: "publicKeyEncryptionKeyPair";
  wrappedPrivateKey!: string;
  publicKey!: string;
  /** `null` for a V1 account. */
  signedPublicKey!: string | null;
}

export class SignatureKeyPairResponse {
  object!: "signatureKeyPair";
  wrappedSigningKey!: string;
  verifyingKey!: string;
}

export class SecurityStateResponse {
  securityState!: string;
  securityVersion!: number;
}

/** The fields of {@link AccountKeysResponse}, which is all a body — parsed or built — holds. */
export type AccountKeysBody = Omit<AccountKeysResponse, "toAccountCryptographicState">;

export class AccountKeysResponse {
  object!: "privateKeys";
  publicKeyEncryptionKeyPair!: PublicKeyEncryptionKeyPairResponse;
  /** `null` for a V1 account, as is {@link securityState}. */
  signatureKeyPair!: SignatureKeyPairResponse | null;
  securityState!: SecurityStateResponse | null;

  /**
   * These keys as an instance, from the fields alone.
   */
  static fromAccountKeysResponse(body: AccountKeysBody): AccountKeysResponse {
    return Object.assign(new AccountKeysResponse(), body);
  }

  /** The account's wrapped private key, whichever generation it is. */
  static wrappedPrivateKeyOf(user: UserEntity): string {
    const state = user.accountCryptographicState;
    return "V1" in state ? state.V1.private_key : state.V2.private_key;
  }

  /**
   * This account's keys in the SDK's `WrappedAccountCryptographicState`.
   *
   * A V1 account carries only a key pair; a V2 account must also carry the signature key pair and
   * security state, which is what makes it V2.
   */
  toAccountCryptographicState(): WrappedAccountCryptographicState {
    const { publicKeyEncryptionKeyPair: pair, signatureKeyPair, securityState } = this;

    if (signatureKeyPair === null || securityState === null) {
      return { V1: { private_key: asEncString(pair.wrappedPrivateKey) } };
    }

    if (pair.signedPublicKey === null) {
      throw new Error("V2 account has no signed public key");
    }

    return {
      V2: {
        private_key: asEncString(pair.wrappedPrivateKey),
        signing_key: asEncString(signatureKeyPair.wrappedSigningKey),
        security_state: asSignedSecurityState(securityState.securityState),
        signed_public_key: asSignedPublicKey(pair.signedPublicKey),
      },
    };
  }

  /** The account's keys as the server serves them. */
  static fromUser(user: UserEntity): AccountKeysResponse {
    const state = user.accountCryptographicState;

    if ("V1" in state) {
      return AccountKeysResponse.fromAccountKeysResponse({
        object: "privateKeys",
        publicKeyEncryptionKeyPair: {
          object: "publicKeyEncryptionKeyPair",
          wrappedPrivateKey: state.V1.private_key,
          publicKey: user.publicKey,
          signedPublicKey: null,
        },
        signatureKeyPair: null,
        securityState: null,
      });
    }

    if (user.verifyingKey === null) {
      throw new Error(`V2 account ${user.email} has no verifying key`);
    }
    if (user.securityVersion === undefined) {
      throw new Error(`V2 account ${user.email} has no security version`);
    }

    return AccountKeysResponse.fromAccountKeysResponse({
      object: "privateKeys",
      publicKeyEncryptionKeyPair: {
        object: "publicKeyEncryptionKeyPair",
        wrappedPrivateKey: state.V2.private_key,
        publicKey: user.publicKey,
        signedPublicKey: state.V2.signed_public_key,
      },
      signatureKeyPair: {
        object: "signatureKeyPair",
        wrappedSigningKey: state.V2.signing_key,
        verifyingKey: user.verifyingKey,
      },
      securityState: {
        securityState: state.V2.security_state,
        securityVersion: user.securityVersion,
      },
    });
  }
}
