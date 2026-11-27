// The request and response models of the organization keys endpoints.

/** The body of `POST /organizations/{orgId}/keys/organization-key-id`. */
export class OrganizationKeyIdRequest {
  organizationKeyId!: string;
}

/** `OrganizationPrivateKeyResponseModel`: the private key wrapped by the organization key. */
export class OrganizationPrivateKeyResponse {
  object!: "organizationPrivateKey";
  privateKey!: string | null;
}

/** `OrganizationPublicKeyResponseModel`. */
export class OrganizationPublicKeyResponse {
  object!: "organizationPublicKey";
  publicKey!: string | null;
}
