// Deterministic plaintext vault for benchmarks: `count` logins named `name_1`, `name_2`, ...
//
// Each login has a username, a password and a URI, so every cipher carries several encrypted
// fields.

import {
  CipherRepromptType,
  CipherType,
  type CipherView,
  type DateTime,
  type Utc,
} from "@bitwarden/sdk-internal";

const DATE = "2024-01-01T00:00:00.000Z" as unknown as DateTime<Utc>;

function login(index: number): CipherView {
  return {
    id: undefined,
    organizationId: undefined,
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
export function generateVault(count: number): CipherView[] {
  return Array.from({ length: count }, (_, i) => login(i + 1));
}
