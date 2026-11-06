// The request models of registering an account and of proving the master password to delete it.

import {
  PublicKeyEncryptionKeyPairRequest,
  SecurityStateRequest,
  SignatureKeyPairRequest,
} from "./account-keys";
import {
  MasterPasswordAuthenticationDataModel,
  MasterPasswordUnlockDataModel,
} from "./master-password";

/** `RegisterSendVerificationEmailRequestModel`, the body of `POST /accounts/register/send-verification-email`. */
export class RegisterSendVerificationEmailRequest {
  email!: string;
  name?: string | null;
  receiveMarketingEmails!: boolean;
}

/** `AccountKeysRequestModel`, as registration posts it. A V1 account sends only the first two. */
export class AccountKeysRequest {
  userKeyEncryptedAccountPrivateKey!: string;
  accountPublicKey!: string;
  publicKeyEncryptionKeyPair?: PublicKeyEncryptionKeyPairRequest | null;
  signatureKeyPair?: SignatureKeyPairRequest | null;
  securityState?: SecurityStateRequest | null;
}

/**
 * `RegisterFinishRequestModel`, the body of `POST /accounts/register/finish`, for an account with a
 * master password that verified its email. The fields for invites and sponsorships are omitted.
 */
export class RegisterFinishRequest {
  email!: string;
  emailVerificationToken?: string | null;
  masterPasswordAuthentication!: MasterPasswordAuthenticationDataModel;
  masterPasswordUnlock!: MasterPasswordUnlockDataModel;
  accountKeys!: AccountKeysRequest;
}

/** `SecretVerificationRequestModel`: proof of possession, as `DELETE /accounts` takes it. */
export class SecretVerificationRequest {
  masterPasswordHash?: string | null;
}
