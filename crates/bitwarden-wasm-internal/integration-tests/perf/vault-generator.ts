// Deterministic plaintext vault for benchmarks: `count` logins named `name_1`, `name_2`, ...
//
// Each login has a username, a password and a URI, so every cipher carries several encrypted
// fields. Every fifth login belongs to the organization, if one is given.

import {
  CipherRepromptType,
  CipherType,
  type CipherView,
  type DateTime,
  type OrganizationId,
  type Utc,
} from "@bitwarden/sdk-internal";

const ORG_EVERY = 5;
const DATE = "2024-01-01T00:00:00.000Z" as unknown as DateTime<Utc>;

function login(index: number, organizationId?: OrganizationId): CipherView {
  return {
    id: undefined,
    organizationId,
    folderId: undefined,
    collectionIds: [],
    key: undefined,
    name: `name_${index}`,
    notes: undefined,
    type: CipherType.Login,
    login: {
      username: `user_${index}@example.com`,
      password: `password_${index}`,
      passwordRevisionDate: undefined,
      uris: [
        {
          uri: `https://site-${index}.example.com/login`,
          match: undefined,
          uriChecksum: undefined,
        },
      ],
      totp: undefined,
      autofillOnPageLoad: undefined,
      fido2Credentials: undefined,
    },
    identity: undefined,
    card: undefined,
    secureNote: undefined,
    sshKey: undefined,
    bankAccount: undefined,
    driversLicense: undefined,
    passport: undefined,
    favorite: false,
    reprompt: CipherRepromptType.None,
    organizationUseTotp: true,
    edit: true,
    permissions: undefined,
    viewPassword: true,
    localData: undefined,
    attachments: undefined,
    fields: undefined,
    passwordHistory: undefined,
    creationDate: DATE,
    deletedDate: undefined,
    revisionDate: DATE,
    archivedDate: undefined,
  };
}

/** Generates `count` logins, `name_1` to `name_<count>`. */
export function generateVault(count: number, orgId?: OrganizationId): CipherView[] {
  return Array.from({ length: count }, (_, i) => {
    const index = i + 1;
    const organizationId = orgId !== undefined && index % ORG_EVERY === 0 ? orgId : undefined;
    return login(index, organizationId);
  });
}
