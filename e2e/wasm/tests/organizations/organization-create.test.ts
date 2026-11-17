import {
  ClientSettings,
  CreateOrganizationRequest,
  InviteSecret,
  isCreateOrganizationError,
  PasswordManagerClient,
} from "@bitwarden/sdk-internal";

import { installHttpMock } from "../../server-emulator/http-mock";
import { TEST_ORGANIZATION_ID, TEST_PROVIDER_ID, TEST_PROVIDER_KEY } from "../org-fixtures";
import { makeOrgAccountClient, makeStateBridge, rejection } from "../utils";
import { inviteLinkRoutes, LINK_CODE, ROUTES as INVITE_LINK_ROUTES } from "./invite-link-server";
import {
  organizationCreateRoutes,
  providerClientCreateRoutes,
  ROUTES,
} from "./organization-create-server";

const TEST_INVITE_SECRET = "oSpRu_AENo_n11TqiLIryrJKaEPbQVjbdd6r4reyqUU" as unknown as InviteSecret;

// Nothing listens here; every request is served by the fetch mock. A concrete host keeps the
// SDK's request URLs parseable and makes an unmocked route fail loudly rather than escape to
// the network.
const SETTINGS: ClientSettings = {
  apiUrl: "http://localhost:4000",
  identityUrl: "http://localhost:4000/identity",
};

const PLAN_TYPE_FREE = 0;
const PLAN_TYPE_TEAMS_ANNUALLY = 18;
const PLAN_TYPE_ENTERPRISE_ANNUALLY = 20;
const PAYMENT_METHOD_CARD = 0;

function freeRequest(): CreateOrganizationRequest {
  return {
    name: "Acme",
    billingEmail: "acme@example.com",
    planType: PLAN_TYPE_FREE,
    initiationPath: undefined,
    kind: { kind: "free", secrets_manager: undefined, pam: undefined },
  };
}

describe("organization create client", () => {
  // Unlocking runs 600k PBKDF2 iterations, so the client is built once per describe block. It
  // holds no per-test state — the mock is what varies between tests.
  let client: PasswordManagerClient;

  beforeAll(async () => {
    client = await makeOrgAccountClient(makeStateBridge(), SETTINGS);
  }, 120_000);

  describe("create_organization", () => {
    afterEach(() => mock?.restore());
    let mock: ReturnType<typeof installHttpMock>;

    it("creates a free organization, sealing the key to the creating user", async () => {
      mock = installHttpMock(organizationCreateRoutes());

      const response = await client
        .organization_create()
        .create_organization("Default", freeRequest());

      expect(mock.routes()).toEqual([ROUTES.createWithoutPayment]);
      const posted = mock.bodyFor(ROUTES.createWithoutPayment);
      expect(posted.name).toBe("Acme");
      expect(posted.billingEmail).toBe("acme@example.com");
      // An `UnsignedSharedKey`: the new organization's key encapsulated to the creating user.
      expect(posted.key).toMatch(/^\d+\./);
      expect(typeof posted.keys.publicKey).toBe("string");
      expect(typeof posted.keys.encryptedPrivateKey).toBe("string");
      // Free organizations never request seats, storage, or payment.
      expect(posted.additionalSeats).toBeUndefined();
      expect(posted.paymentMethodType).toBeUndefined();

      expect(typeof response.organizationId).toBe("string");
    });

    it("creates a trial organization with seats and no payment", async () => {
      mock = installHttpMock(organizationCreateRoutes());

      await client.organization_create().create_organization("Default", {
        name: "Acme",
        billingEmail: "acme@example.com",
        planType: PLAN_TYPE_TEAMS_ANNUALLY,
        initiationPath: undefined,
        kind: {
          kind: "trial",
          seats: { additionalSeats: 5, additionalStorageGb: 0 },
          secrets_manager: undefined,
          pam: undefined,
          trial_length: undefined,
        },
      });

      expect(mock.routes()).toEqual([ROUTES.createWithoutPayment]);
      const posted = mock.bodyFor(ROUTES.createWithoutPayment);
      expect(posted.additionalSeats).toBe(5);
      expect(posted.paymentMethodType).toBeUndefined();
      expect(posted.paymentToken).toBeUndefined();
    });

    it("creates a paid organization with seats and payment", async () => {
      mock = installHttpMock(organizationCreateRoutes());

      await client.organization_create().create_organization("Default", {
        name: "Acme",
        billingEmail: "acme@example.com",
        planType: PLAN_TYPE_ENTERPRISE_ANNUALLY,
        initiationPath: undefined,
        kind: {
          kind: "paid",
          seats: { additionalSeats: 10, additionalStorageGb: 1 },
          payment: {
            paymentMethodType: PAYMENT_METHOD_CARD,
            paymentToken: "tok_123",
            premiumAccessAddon: false,
            billingAddress: {
              line1: undefined,
              line2: undefined,
              city: undefined,
              state: undefined,
              postalCode: undefined,
              country: undefined,
              taxId: undefined,
            },
          },
          secrets_manager: undefined,
          pam: undefined,
          coupons: [],
          trial_length: undefined,
        },
      });

      expect(mock.routes()).toEqual([ROUTES.create]);
      const posted = mock.bodyFor(ROUTES.create);
      expect(posted.additionalSeats).toBe(10);
      expect(posted.paymentToken).toBe("tok_123");
      expect(posted.paymentMethodType).toBe(PAYMENT_METHOD_CARD);
    });

    it("rejects PAM before making any request", async () => {
      mock = installHttpMock(organizationCreateRoutes());

      const request = freeRequest();
      request.kind = {
        kind: "free",
        secrets_manager: undefined,
        pam: { pamSeats: 5 },
      };

      const error = await rejection(
        client.organization_create().create_organization("Default", request),
        isCreateOrganizationError,
      );

      expect(error.variant).toBe("PamNotSupported");
      expect(mock.routes()).toEqual([]);
    });

    describe("ProviderClient", () => {
      let providerClient: PasswordManagerClient;

      beforeAll(async () => {
        providerClient = await makeOrgAccountClient(makeStateBridge(), SETTINGS);
        await providerClient.crypto().initialize_provider_crypto({
          providerKeys: new Map([[TEST_PROVIDER_ID, TEST_PROVIDER_KEY]]),
        });
      }, 120_000);

      it("wraps the organization key to the provider and posts to the clients endpoint", async () => {
        const providerId = TEST_PROVIDER_ID as unknown as string;
        mock = installHttpMock(providerClientCreateRoutes(providerId));

        const response = await providerClient.organization_create().create_organization("Default", {
          name: "Acme",
          billingEmail: "acme@example.com",
          planType: PLAN_TYPE_ENTERPRISE_ANNUALLY,
          initiationPath: undefined,
          kind: {
            kind: "providerClient",
            seats: 10,
            provider: {
              providerId: TEST_PROVIDER_ID,
              clientOwnerEmail: "owner@example.com",
            },
          },
        });

        const route = ROUTES.providerClientCreate(providerId);
        expect(mock.routes()).toEqual([route]);

        const posted = mock.bodyFor(route);
        expect(posted.name).toBe("Acme");
        expect(posted.ownerEmail).toBe("owner@example.com");
        expect(posted.seats).toBe(10);
        // An `EncString`: the organization key symmetrically wrapped with the provider's key,
        // not encapsulated to an RSA public key (there is no such thing as a provider keypair).
        expect(posted.key).toMatch(/^2\./);
        expect(typeof posted.keyPair.publicKey).toBe("string");
        expect(typeof posted.keyPair.encryptedPrivateKey).toBe("string");
        // The endpoint has no payment, Secrets Manager, coupon, or trial-length fields.
        expect(posted).not.toHaveProperty("payment");
        expect(posted).not.toHaveProperty("secretsManager");
        expect(posted).not.toHaveProperty("coupons");
        expect(posted).not.toHaveProperty("trialLength");

        // `POST /providers/{providerId}/clients` returns no body, so there is no organization id
        // to report yet.
        expect(response.organizationId).toBe("00000000-0000-0000-0000-000000000000");
      });
    });
  });

  it("round-trips a provider-created organization into an invitee enrolling via invite link", async () => {
    // 1. A provider creates a client organization. The server hands back only an
    //    acknowledgement; the test stands in for the server's side of the hand-off by seeding the
    //    invite-link mock with a fixed invite for `TEST_ORGANIZATION_ID`, the same organization
    //    `TEST_INVITE` is bound to.
    const providerClient = await makeOrgAccountClient(makeStateBridge(), SETTINGS);
    await providerClient.crypto().initialize_provider_crypto({
      providerKeys: new Map([[TEST_PROVIDER_ID, TEST_PROVIDER_KEY]]),
    });

    const providerId = TEST_PROVIDER_ID as unknown as string;
    let mock = installHttpMock(providerClientCreateRoutes(providerId));

    await providerClient.organization_create().create_organization("Default", {
      name: "Acme",
      billingEmail: "acme@example.com",
      planType: PLAN_TYPE_ENTERPRISE_ANNUALLY,
      initiationPath: undefined,
      kind: {
        kind: "providerClient",
        seats: 10,
        provider: {
          providerId: TEST_PROVIDER_ID,
          clientOwnerEmail: "owner@example.com",
        },
      },
    });

    expect(mock.routes()).toEqual([ROUTES.providerClientCreate(providerId)]);
    mock.restore();

    // 2. The invited owner redeems the invite link the provider's client org sent, enrolling into
    //    account recovery at the same time — the complete flow from org creation through to a new
    //    member who can both read the vault and be recovered by an admin.
    const invitee = await makeOrgAccountClient(makeStateBridge(), SETTINGS);
    mock = installHttpMock(inviteLinkRoutes());

    await invitee
      .invite_link()
      .user()
      .accept_and_optionally_confirm(
        TEST_ORGANIZATION_ID,
        LINK_CODE,
        TEST_INVITE_SECRET,
        "My Items",
        true,
      );

    expect(mock.routes()).toEqual([
      INVITE_LINK_ROUTES.publicKey,
      INVITE_LINK_ROUTES.getInvite,
      INVITE_LINK_ROUTES.confirm,
    ]);

    const confirmed = mock.bodyFor(INVITE_LINK_ROUTES.confirm);
    expect(confirmed.organizationId).toBe(TEST_ORGANIZATION_ID);
    // The invitee now holds the organization key (self-confirmed) and has enrolled into account
    // recovery, both in the same request.
    expect(typeof confirmed.orgUserKey).toBe("string");
    expect(typeof confirmed.resetPasswordKey).toBe("string");

    mock.restore();
  }, 120_000);
});
