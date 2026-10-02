// Deterministic generator for large, realistic plaintext vaults.
//
// The mix approximates a long-lived personal + organization vault: mostly logins, some with
// several URIs, TOTP, notes, custom fields and password history; plus cards, identities and
// secure notes. A seeded PRNG keeps every run identical so timings are comparable.

import {
  CipherRepromptType,
  CipherType,
  FieldType,
  SecureNoteType,
  UriMatchType,
  type CipherId,
  type CipherView,
  type DateTime,
  type FieldView,
  type OrganizationId,
  type PasswordHistoryView,
  type Utc,
} from "@bitwarden/sdk-internal";

const SEED = 0xb17;
const ORG_SHARE = 0.2;
const DATE = "2024-01-01T00:00:00.000Z" as unknown as DateTime<Utc>;

// Share of each cipher type. Remainder after these is logins.
const SECURE_NOTE_SHARE = 0.08;
const CARD_SHARE = 0.06;
const IDENTITY_SHARE = 0.04;

/** Mulberry32: tiny, seedable, good enough for test data. */
function prng(seed: number): () => number {
  let state = seed;
  return () => {
    state = (state + 0x6d2b79f5) | 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

class Gen {
  private readonly rand = prng(SEED);

  chance(p: number): boolean {
    return this.rand() < p;
  }

  int(min: number, max: number): number {
    return min + Math.floor(this.rand() * (max - min + 1));
  }

  text(min: number, max: number): string {
    const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ._-";
    const len = this.int(min, max);
    let out = "";
    for (let i = 0; i < len; i++) {
      out += alphabet[Math.floor(this.rand() * alphabet.length)];
    }
    return out;
  }

  uuid(): string {
    const hex = () => Math.floor(this.rand() * 16).toString(16);
    const part = (n: number) => Array.from({ length: n }, hex).join("");
    return `${part(8)}-${part(4)}-4${part(3)}-8${part(3)}-${part(12)}`;
  }
}

function emptyView(gen: Gen, type: CipherType, organizationId?: OrganizationId): CipherView {
  return {
    id: gen.uuid() as unknown as CipherId,
    organizationId,
    folderId: undefined,
    collectionIds: [],
    key: undefined,
    name: gen.text(6, 30),
    notes: gen.chance(0.25) ? gen.text(20, 400) : undefined,
    type,
    login: undefined,
    identity: undefined,
    card: undefined,
    secureNote: undefined,
    sshKey: undefined,
    bankAccount: undefined,
    driversLicense: undefined,
    passport: undefined,
    favorite: gen.chance(0.05),
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

function fields(gen: Gen): FieldView[] | undefined {
  if (!gen.chance(0.15)) {
    return undefined;
  }
  return Array.from({ length: gen.int(1, 4) }, () => ({
    name: gen.text(4, 16),
    value: gen.text(4, 40),
    type: gen.chance(0.5) ? FieldType.Text : FieldType.Hidden,
    linkedId: undefined,
  }));
}

function history(gen: Gen): PasswordHistoryView[] | undefined {
  if (!gen.chance(0.2)) {
    return undefined;
  }
  return Array.from({ length: gen.int(1, 5) }, () => ({
    password: gen.text(12, 32),
    lastUsedDate: DATE,
  }));
}

function login(gen: Gen, view: CipherView): CipherView {
  view.login = {
    username: gen.text(6, 32),
    password: gen.text(12, 32),
    passwordRevisionDate: undefined,
    uris: Array.from({ length: gen.int(0, 3) }, () => ({
      uri: `https://${gen.text(4, 20).replace(/[^a-z0-9]/gi, "x")}.example.com/${gen.text(0, 30)}`,
      match: gen.chance(0.8) ? undefined : UriMatchType.Host,
      uriChecksum: undefined,
    })),
    totp: gen.chance(0.1) ? "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP" : undefined,
    autofillOnPageLoad: undefined,
    fido2Credentials: undefined,
  };
  view.fields = fields(gen);
  view.passwordHistory = history(gen);
  return view;
}

function card(gen: Gen, view: CipherView): CipherView {
  view.card = {
    cardholderName: gen.text(8, 24),
    expMonth: String(gen.int(1, 12)),
    expYear: String(gen.int(2025, 2035)),
    code: String(gen.int(100, 999)),
    brand: "Visa",
    number: "4111111111111111",
  };
  return view;
}

function identity(gen: Gen, view: CipherView): CipherView {
  const t = () => (gen.chance(0.6) ? gen.text(3, 20) : undefined);
  view.identity = {
    title: t(),
    firstName: t(),
    middleName: t(),
    lastName: t(),
    address1: t(),
    address2: t(),
    address3: t(),
    city: t(),
    state: t(),
    postalCode: t(),
    country: t(),
    company: t(),
    email: t(),
    phone: t(),
    ssn: t(),
    username: t(),
    passportNumber: t(),
    licenseNumber: t(),
  };
  return view;
}

/** Generates `count` plaintext cipher views. `orgId`, if set, receives roughly 20% of them. */
export function generateVault(count: number, orgId?: OrganizationId): CipherView[] {
  const gen = new Gen();
  const views: CipherView[] = [];

  for (let i = 0; i < count; i++) {
    // Drawn even without an org so every scenario gets the same item sequence.
    const org = gen.chance(ORG_SHARE) ? orgId : undefined;
    const r = gen.int(0, 999) / 1000;

    if (r < SECURE_NOTE_SHARE) {
      const view = emptyView(gen, CipherType.SecureNote, org);
      view.secureNote = { type: SecureNoteType.Generic };
      view.notes = gen.text(50, 2000);
      views.push(view);
      continue;
    }
    if (r < SECURE_NOTE_SHARE + CARD_SHARE) {
      views.push(card(gen, emptyView(gen, CipherType.Card, org)));
      continue;
    }
    if (r < SECURE_NOTE_SHARE + CARD_SHARE + IDENTITY_SHARE) {
      views.push(identity(gen, emptyView(gen, CipherType.Identity, org)));
      continue;
    }
    views.push(login(gen, emptyView(gen, CipherType.Login, org)));
  }

  return views;
}
