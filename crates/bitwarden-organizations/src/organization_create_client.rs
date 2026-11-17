use std::sync::Arc;

use bitwarden_api_api::models::{
    CreateClientOrganizationRequestBody, OrganizationCreateRequestModel,
    OrganizationKeysRequestModel, OrganizationNoPaymentCreateRequest,
};
use bitwarden_core::{
    ApiError, Client, FromClient, MissingFieldError, OrganizationId,
    client::ApiConfigurations,
    key_management::{KeySlotIds, PrivateKeySlotId, SymmetricKeySlotId},
    require,
};
use bitwarden_crypto::{
    CryptoError, KeyStore, PrimitiveEncryptable, PublicKeyEncryptionAlgorithm,
    SymmetricKeyAlgorithm,
};
use bitwarden_encoding::B64;
use bitwarden_error::bitwarden_error;
use bitwarden_organization_crypto::{
    organization_shared_key::{OrganizationSharedKey, OrganizationSharedKeyMakeError},
    trust_proof::{CryptographicProof, TrustProof},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ProviderId;

/// Secrets Manager add-on details for a new organization.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
pub struct SecretsManagerDetails {
    /// Additional Secrets Manager seats beyond those included in the base plan.
    pub additional_sm_seats: i32,
    /// Additional Secrets Manager service accounts beyond those included in the base plan.
    pub additional_service_accounts: i32,
    /// Whether this subscription originated from a Secrets Manager trial.
    pub is_from_secrets_manager_trial: bool,
}

/// Privileged Access Manager add-on details for a new organization.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
pub struct PamDetails {
    /// Additional Privileged Access Manager seats beyond those included in the base plan.
    pub pam_seats: i32,
}

/// Seat and storage details for a new organization.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
pub struct SeatDetails {
    /// Additional member seats beyond those included in the base plan.
    pub additional_seats: i32,
    /// Additional encrypted storage, in gigabytes, beyond what's included in the base plan.
    pub additional_storage_gb: i32,
}

/// A billing address for a new organization.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
pub struct BillingAddress {
    /// The first line of the street address.
    pub line1: Option<String>,
    /// The second line of the street address.
    pub line2: Option<String>,
    /// The city.
    pub city: Option<String>,
    /// The state or province.
    pub state: Option<String>,
    /// The postal or ZIP code.
    pub postal_code: Option<String>,
    /// The ISO 3166-1 country code.
    pub country: Option<String>,
    /// The tax identification number, when applicable.
    pub tax_id: Option<String>,
}

/// Payment details for a new organization.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
pub struct PaymentDetails {
    /// The payment method used for the subscription, matching the server's `PaymentMethodType`
    /// enum discriminant (TypeScript already owns and sends this value today).
    pub payment_method_type: i32,
    /// The opaque payment token (for example, a Braintree or Stripe payment method nonce).
    pub payment_token: String,
    /// Whether the premium access add-on is included.
    pub premium_access_addon: bool,
    /// The billing address for invoicing and tax calculation.
    pub billing_address: BillingAddress,
}

/// Provider-specific details when creating an organization on behalf of a provider's client.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
pub struct ProviderCreateDetails {
    /// The provider creating the organization on behalf of its client.
    pub provider_id: ProviderId,
    /// The email address of the client organization's owner.
    pub client_owner_email: String,
}

/// Fields for [`Kind::Free`].
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
pub struct FreeDetails {
    /// Optional Secrets Manager subscription.
    pub secrets_manager: Option<SecretsManagerDetails>,
    /// Optional Privileged Access Manager subscription.
    pub pam: Option<PamDetails>,
}

/// Fields for [`Kind::Paid`].
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
pub struct PaidDetails {
    /// Seat and storage allotment.
    pub seats: SeatDetails,
    /// Payment details.
    pub payment: PaymentDetails,
    /// Optional Secrets Manager subscription.
    pub secrets_manager: Option<SecretsManagerDetails>,
    /// Optional Privileged Access Manager subscription.
    pub pam: Option<PamDetails>,
    /// Coupon codes to apply.
    pub coupons: Vec<String>,
    /// Trial length, in days, when applicable.
    pub trial_length: Option<i32>,
    /// Whether to skip the trial period and bill immediately.
    pub skip_trial: bool,
}

/// Fields for [`Kind::Trial`].
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
pub struct TrialDetails {
    /// Seat and storage allotment.
    pub seats: SeatDetails,
    /// Optional Secrets Manager subscription.
    pub secrets_manager: Option<SecretsManagerDetails>,
    /// Optional Privileged Access Manager subscription.
    pub pam: Option<PamDetails>,
    /// Trial length, in days, when applicable.
    pub trial_length: Option<i32>,
}

/// Fields for [`Kind::ProviderClient`].
///
/// Posted to `POST /providers/{providerId}/clients`, which has no fields for payment,
/// Secrets Manager, PAM, coupons, trial length, or additional storage: the provider is already
/// billed directly, so none of that applies to a provider-created client organization.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
pub struct ProviderClientDetails {
    /// The number of member seats to allot.
    pub seats: i32,
    /// The provider creating this organization.
    pub provider: ProviderCreateDetails,
}

/// Fields for [`Kind::UpgradeFromPremium`].
///
/// Posted to `POST /account/billing/vnext/upgrade`, which converts the user's existing premium
/// subscription into an organization. It takes neither seats nor payment details: the user already
/// has a payment method on file, and the target tier determines the seat allotment.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
pub struct UpgradeFromPremiumDetails {
    /// The product tier to upgrade to, matching the server's `ProductTierType` enum discriminant.
    pub target_product_tier_type: i32,
    /// The billing address used to calculate tax on the new organization.
    pub billing_address: BillingAddress,
}

/// The shape of a new organization, determining which fields are required and which server
/// endpoint creates it.
///
/// Each variant wraps a named struct (rather than inline fields) so that `Tsify` applies
/// `rename_all = "camelCase"` to the payload: Tsify does not propagate an enum's `rename_all`
/// into inline struct-variant fields, only into separately-derived structs.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", tag = "kind", content = "value")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[bitwarden_ffi::wasm_record]
pub enum Kind {
    /// A free organization. Never includes seats, storage, or payment.
    Free(FreeDetails),
    /// A paid organization with an active payment method.
    Paid(PaidDetails),
    /// A Teams or Enterprise trial organization created without a payment method.
    Trial(TrialDetails),
    /// An organization created by a provider on behalf of one of its clients.
    ProviderClient(ProviderClientDetails),
    /// A premium user upgrading their existing subscription directly into a paid organization.
    UpgradeFromPremium(UpgradeFromPremiumDetails),
}

/// Request to create a new organization.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
pub struct CreateOrganizationRequest {
    /// The organization's display name.
    pub name: String,
    /// The organization's legal business name, when it differs from the display name.
    pub business_name: Option<String>,
    /// The billing email address.
    pub billing_email: String,
    /// The subscription plan, matching the server's `PlanType` enum discriminant (TypeScript
    /// already owns and sends this value today).
    ///
    /// Not applicable to [`Kind::UpgradeFromPremium`], which selects the plan with
    /// [`UpgradeFromPremiumDetails::target_product_tier_type`] instead.
    pub plan_type: Option<i32>,
    /// Where the creation flow was initiated from, for attribution.
    pub initiation_path: Option<String>,
    /// The organization's shape, determining required fields and the server endpoint used.
    pub kind: Kind,
}

/// The response to a successful organization creation.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
pub struct CreateOrganizationResponse {
    /// The newly created organization's ID.
    pub organization_id: OrganizationId,
}

/// Errors returned from [`OrganizationCreateClient`] operations.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum CreateOrganizationError {
    /// The request failed as a whole.
    #[error(transparent)]
    Api(#[from] ApiError),
    /// A cryptographic operation (key generation, wrapping, or encapsulation) failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// Sealing the organization key to the creating user's public key failed.
    #[error(transparent)]
    OrganizationSharedKey(#[from] OrganizationSharedKeyMakeError),
    /// A required field was missing from the server response.
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
}

/// Client for creating new organizations.
#[bitwarden_ffi::wasm_object]
#[derive(FromClient)]
pub struct OrganizationCreateClient {
    pub(crate) key_store: KeyStore<KeySlotIds>,
    pub(crate) api_configurations: Arc<ApiConfigurations>,
}

#[bitwarden_ffi::wasm_export]
impl OrganizationCreateClient {
    /// Creates a new organization. Generates the organization's keys locally; only encrypted key
    /// material ever leaves this method.
    pub async fn create_organization(
        &self,
        default_collection_name: String,
        request: CreateOrganizationRequest,
    ) -> Result<CreateOrganizationResponse, CreateOrganizationError> {
        let organization_id = match &request.kind {
            Kind::Free(FreeDetails {
                secrets_manager,
                pam,
            }) => {
                let (key, org_keys, collection_name) =
                    self.seal_to_self(&default_collection_name)?;
                let model = build_no_payment_request(
                    &request,
                    key,
                    org_keys,
                    collection_name,
                    None,
                    secrets_manager,
                    pam,
                    None,
                );
                let response = self
                    .api_configurations
                    .api_client
                    .organizations_api()
                    .create_without_payment(Some(model))
                    .await?;
                require!(response.id)
            }
            Kind::Trial(TrialDetails {
                seats,
                secrets_manager,
                pam,
                trial_length,
            }) => {
                let (key, org_keys, collection_name) =
                    self.seal_to_self(&default_collection_name)?;
                let model = build_no_payment_request(
                    &request,
                    key,
                    org_keys,
                    collection_name,
                    Some(seats),
                    secrets_manager,
                    pam,
                    *trial_length,
                );
                let response = self
                    .api_configurations
                    .api_client
                    .organizations_api()
                    .create_without_payment(Some(model))
                    .await?;
                require!(response.id)
            }
            Kind::Paid(PaidDetails {
                seats,
                payment,
                secrets_manager,
                pam,
                coupons,
                trial_length,
                skip_trial,
            }) => {
                let (key, org_keys, collection_name) =
                    self.seal_to_self(&default_collection_name)?;
                let model = build_paid_request(
                    &request,
                    key,
                    org_keys,
                    collection_name,
                    seats,
                    payment,
                    secrets_manager,
                    pam,
                    coupons,
                    *trial_length,
                    *skip_trial,
                );
                let response = self
                    .api_configurations
                    .api_client
                    .organizations_api()
                    .post(Some(model))
                    .await?;
                require!(response.id)
            }
            Kind::ProviderClient(ProviderClientDetails { seats, provider }) => {
                let (key, org_keys, collection_name) =
                    self.seal_to_provider(&default_collection_name, provider.provider_id)?;
                let key_pair = bitwarden_api_api::models::KeyPairRequestBody::new(
                    org_keys.public_key,
                    org_keys.encrypted_private_key,
                );
                let mut model = CreateClientOrganizationRequestBody::new(
                    request.name.clone(),
                    provider.client_owner_email.clone(),
                    key,
                    key_pair,
                    collection_name,
                );
                model.plan_type = request.plan_type.map(|plan_type| {
                    bitwarden_api_api::models::PlanType::from_i64(plan_type as i64)
                });
                model.seats = Some(*seats);
                self.api_configurations
                    .api_client
                    .provider_clients_api()
                    .create(provider.provider_id.into(), Some(model))
                    .await?;
                uuid::Uuid::nil()
            }
            Kind::UpgradeFromPremium(UpgradeFromPremiumDetails {
                target_product_tier_type,
                billing_address,
            }) => {
                let (key, org_keys, collection_name) =
                    self.seal_to_self(&default_collection_name)?;

                // This endpoint takes only country and postal code: the premium subscription
                // already on file supplies the rest of the billing details.
                let billing_address_request =
                    bitwarden_api_api::models::CheckoutBillingAddressRequest {
                        country: billing_address.country.clone().unwrap_or_default(),
                        postal_code: billing_address.postal_code.clone().unwrap_or_default(),
                        tax_id: None,
                    };

                let mut model = bitwarden_api_api::models::UpgradePremiumToOrganizationRequest::new(
                    request.name.clone(),
                    key,
                    org_keys.public_key,
                    org_keys.encrypted_private_key,
                    bitwarden_api_api::models::ProductTierType::from_i64(
                        *target_product_tier_type as i64,
                    ),
                    billing_address_request,
                );
                model.collection_name = Some(collection_name);

                let response = self
                    .api_configurations
                    .api_client
                    .account_billing_v_next_api()
                    .upgrade_premium_to_organization(Some(model))
                    .await?;
                require!(response.organization_id)
            }
        };

        Ok(CreateOrganizationResponse {
            organization_id: OrganizationId::new(organization_id),
        })
    }

    /// Generates a new organization key, keypair, and encrypted default collection name, sealing
    /// the organization key to the creating user's own public key. The creating user holds their
    /// own private key in this context, so the key is cryptographically provable as belonging to
    /// them.
    fn seal_to_self(
        &self,
        default_collection_name: &str,
    ) -> Result<(String, OrganizationKeysRequestModel, String), CreateOrganizationError> {
        let mut ctx = self.key_store.context();

        let org_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let user_public_key = ctx.get_public_key(PrivateKeySlotId::UserPrivateKey)?;
        let key = String::from(&OrganizationSharedKey::make(
            org_key_id,
            &user_public_key,
            &TrustProof::CryptographicallyTrusted(CryptographicProof::OwnPrivateKey(
                PrivateKeySlotId::UserPrivateKey,
            )),
            &ctx,
        )?);

        self.finish_sealing(&mut ctx, org_key_id, default_collection_name, key)
    }

    /// Generates a new organization key, keypair, and encrypted default collection name, sealing
    /// the organization key to `provider_id`'s own symmetric key instead of the creating user's.
    fn seal_to_provider(
        &self,
        default_collection_name: &str,
        provider_id: ProviderId,
    ) -> Result<(String, OrganizationKeysRequestModel, String), CreateOrganizationError> {
        let mut ctx = self.key_store.context();

        let org_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let key = ctx
            .wrap_symmetric_key(SymmetricKeySlotId::Provider(provider_id), org_key_id)?
            .to_string();

        self.finish_sealing(&mut ctx, org_key_id, default_collection_name, key)
    }

    /// Shared tail of [`Self::seal_to_self`] and [`Self::seal_to_provider`]: generates the
    /// organization's keypair and encrypts the default collection name, now that `key` holds the
    /// sealed organization key.
    fn finish_sealing(
        &self,
        ctx: &mut bitwarden_crypto::KeyStoreContext<'_, KeySlotIds>,
        org_key_id: <KeySlotIds as bitwarden_crypto::KeySlotIds>::Symmetric,
        default_collection_name: &str,
        key: String,
    ) -> Result<(String, OrganizationKeysRequestModel, String), CreateOrganizationError> {
        let private_key_id = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let public_key = String::from(&B64::from(
            ctx.get_public_key(private_key_id)?.to_der()?.as_ref(),
        ));
        let wrapped_private_key = ctx
            .wrap_private_key(org_key_id, private_key_id)?
            .to_string();

        let collection_name = default_collection_name
            .to_string()
            .encrypt(ctx, org_key_id)?
            .to_string();

        Ok((
            key,
            OrganizationKeysRequestModel::new(public_key, wrapped_private_key),
            collection_name,
        ))
    }
}

/// Builds the request body for `Kind::Free`/`Kind::Trial`, both posted to
/// `POST /organizations/create-without-payment`.
#[allow(clippy::too_many_arguments)]
fn build_no_payment_request(
    request: &CreateOrganizationRequest,
    key: String,
    keys: OrganizationKeysRequestModel,
    collection_name: String,
    seats: Option<&SeatDetails>,
    secrets_manager: &Option<SecretsManagerDetails>,
    pam: &Option<PamDetails>,
    trial_length: Option<i32>,
) -> OrganizationNoPaymentCreateRequest {
    let mut model = OrganizationNoPaymentCreateRequest::new(
        request.name.clone(),
        request.billing_email.clone(),
        key,
        keys,
        secrets_manager.is_some(),
    );
    model.business_name = request.business_name.clone();
    model.plan_type = request
        .plan_type
        .map(|plan_type| bitwarden_api_api::models::PlanType::from_i64(plan_type as i64));
    model.initiation_path = request.initiation_path.clone();
    model.collection_name = Some(collection_name);
    model.trial_length = trial_length;
    if let Some(seats) = seats {
        model.additional_seats = Some(seats.additional_seats);
        model.additional_storage_gb = Some(seats.additional_storage_gb);
    }
    if let Some(secrets_manager) = secrets_manager {
        model.additional_sm_seats = Some(secrets_manager.additional_sm_seats);
        model.additional_service_accounts = Some(secrets_manager.additional_service_accounts);
        model.is_from_secrets_manager_trial = Some(secrets_manager.is_from_secrets_manager_trial);
    }
    if let Some(pam) = pam {
        model.use_privileged_controls = Some(true);
        model.pam_seats = Some(pam.pam_seats);
    }
    model
}

/// Builds the request body for `Kind::Paid`, posted with `OrganizationCreateRequestModel`.
#[allow(clippy::too_many_arguments)]
fn build_paid_request(
    request: &CreateOrganizationRequest,
    key: String,
    keys: OrganizationKeysRequestModel,
    collection_name: String,
    seats: &SeatDetails,
    payment: &PaymentDetails,
    secrets_manager: &Option<SecretsManagerDetails>,
    pam: &Option<PamDetails>,
    coupons: &[String],
    trial_length: Option<i32>,
    skip_trial: bool,
) -> OrganizationCreateRequestModel {
    let mut model = OrganizationCreateRequestModel::new(
        request.name.clone(),
        request.billing_email.clone(),
        key,
        keys,
        secrets_manager.is_some(),
    );
    model.business_name = request.business_name.clone();
    model.plan_type = request
        .plan_type
        .map(|plan_type| bitwarden_api_api::models::PlanType::from_i64(plan_type as i64));
    model.initiation_path = request.initiation_path.clone();
    model.collection_name = Some(collection_name);
    model.additional_seats = Some(seats.additional_seats);
    model.additional_storage_gb = Some(seats.additional_storage_gb);
    model.payment_method_type = Some(bitwarden_api_api::models::PaymentMethodType::from_i64(
        payment.payment_method_type as i64,
    ));
    model.payment_token = Some(payment.payment_token.clone());
    model.premium_access_addon = Some(payment.premium_access_addon);
    model.tax_id_number = payment.billing_address.tax_id.clone();
    model.billing_address_line1 = payment.billing_address.line1.clone();
    model.billing_address_line2 = payment.billing_address.line2.clone();
    model.billing_address_city = payment.billing_address.city.clone();
    model.billing_address_state = payment.billing_address.state.clone();
    model.billing_address_postal_code = payment.billing_address.postal_code.clone();
    model.billing_address_country = payment.billing_address.country.clone();
    model.trial_length = trial_length;
    model.skip_trial = Some(skip_trial);
    model.coupons = if coupons.is_empty() {
        None
    } else {
        Some(coupons.to_vec())
    };
    if let Some(secrets_manager) = secrets_manager {
        model.additional_sm_seats = Some(secrets_manager.additional_sm_seats);
        model.additional_service_accounts = Some(secrets_manager.additional_service_accounts);
        model.is_from_secrets_manager_trial = Some(secrets_manager.is_from_secrets_manager_trial);
    }
    if let Some(pam) = pam {
        model.use_privileged_controls = Some(true);
        model.pam_seats = Some(pam.pam_seats);
    }
    model
}

/// Extension trait exposing [`OrganizationCreateClient`] on [`Client`].
pub trait OrganizationCreateClientExt {
    /// Organization creation operations.
    fn organization_create(&self) -> OrganizationCreateClient;
}

impl OrganizationCreateClientExt for Client {
    fn organization_create(&self) -> OrganizationCreateClient {
        OrganizationCreateClient::from_client(self)
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{apis::ApiClient, models::OrganizationResponseModel};
    use bitwarden_core::key_management::{
        PrivateKeySlotId, create_test_crypto_with_user_and_org_key,
    };
    use bitwarden_crypto::{PublicKeyEncryptionAlgorithm, SymmetricCryptoKey};

    use super::*;

    const PLAN_TYPE_FREE: i32 = 0;
    const PLAN_TYPE_ENTERPRISE_ANNUALLY: i32 = 20;
    const PLAN_TYPE_TEAMS_ANNUALLY: i32 = 18;
    const PAYMENT_METHOD_CARD: i32 = 0;
    const PRODUCT_TIER_ENTERPRISE: i32 = 3;

    fn make_client(api_client: ApiClient) -> OrganizationCreateClient {
        let user_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let key_store =
            create_test_crypto_with_user_and_org_key(user_key, OrganizationId::new_v4(), org_key);
        {
            let mut ctx = key_store.context_mut();
            let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
            #[allow(deprecated)]
            ctx.persist_private_key(private_key, PrivateKeySlotId::UserPrivateKey)
                .unwrap();
        }
        OrganizationCreateClient {
            key_store,
            api_configurations: Arc::new(ApiConfigurations::from_api_client(api_client)),
        }
    }

    fn no_pam_seats() -> Option<PamDetails> {
        None
    }

    #[tokio::test]
    async fn free_posts_to_create_without_payment_with_no_seats() {
        let org_id = uuid::Uuid::new_v4();
        let client = make_client(ApiClient::new_mocked(move |mock| {
            mock.organizations_api
                .expect_create_without_payment()
                .withf(|model| {
                    let model = model.as_ref().unwrap();
                    model.additional_seats.is_none()
                        && model.additional_storage_gb.is_none()
                        && model.payment_method_type.is_none()
                })
                .returning(move |_| {
                    Ok(OrganizationResponseModel {
                        id: Some(org_id),
                        ..Default::default()
                    })
                })
                .once();
        }));

        let response = client
            .create_organization(
                "Default".to_string(),
                CreateOrganizationRequest {
                    name: "Acme".to_string(),
                    business_name: None,
                    billing_email: "acme@example.com".to_string(),
                    plan_type: Some(PLAN_TYPE_FREE),
                    initiation_path: None,
                    kind: Kind::Free(FreeDetails {
                        secrets_manager: None,
                        pam: no_pam_seats(),
                    }),
                },
            )
            .await
            .unwrap();

        assert_eq!(response.organization_id, OrganizationId::new(org_id));
    }

    #[tokio::test]
    async fn trial_posts_to_create_without_payment_with_seats_and_no_payment() {
        let org_id = uuid::Uuid::new_v4();
        let client = make_client(ApiClient::new_mocked(move |mock| {
            mock.organizations_api
                .expect_create_without_payment()
                .withf(|model| {
                    let model = model.as_ref().unwrap();
                    model.additional_seats == Some(5)
                        && model.payment_method_type.is_none()
                        && model.payment_token.is_none()
                })
                .returning(move |_| {
                    Ok(OrganizationResponseModel {
                        id: Some(org_id),
                        ..Default::default()
                    })
                })
                .once();
        }));

        let response = client
            .create_organization(
                "Default".to_string(),
                CreateOrganizationRequest {
                    name: "Acme".to_string(),
                    business_name: None,
                    billing_email: "acme@example.com".to_string(),
                    plan_type: Some(PLAN_TYPE_TEAMS_ANNUALLY),
                    initiation_path: None,
                    kind: Kind::Trial(TrialDetails {
                        seats: SeatDetails {
                            additional_seats: 5,
                            additional_storage_gb: 0,
                        },
                        secrets_manager: None,
                        pam: no_pam_seats(),
                        trial_length: None,
                    }),
                },
            )
            .await
            .unwrap();

        assert_eq!(response.organization_id, OrganizationId::new(org_id));
    }

    #[tokio::test]
    async fn paid_posts_with_seats_and_payment() {
        let org_id = uuid::Uuid::new_v4();
        let client = make_client(ApiClient::new_mocked(move |mock| {
            mock.organizations_api
                .expect_post()
                .withf(|model| {
                    let model = model.as_ref().unwrap();
                    model.additional_seats == Some(10)
                        && model.payment_token.as_deref() == Some("tok_123")
                })
                .returning(move |_| {
                    Ok(OrganizationResponseModel {
                        id: Some(org_id),
                        ..Default::default()
                    })
                })
                .once();
        }));

        let response = client
            .create_organization(
                "Default".to_string(),
                CreateOrganizationRequest {
                    name: "Acme".to_string(),
                    business_name: None,
                    billing_email: "acme@example.com".to_string(),
                    plan_type: Some(PLAN_TYPE_ENTERPRISE_ANNUALLY),
                    initiation_path: None,
                    kind: Kind::Paid(PaidDetails {
                        seats: SeatDetails {
                            additional_seats: 10,
                            additional_storage_gb: 1,
                        },
                        payment: PaymentDetails {
                            payment_method_type: PAYMENT_METHOD_CARD,
                            payment_token: "tok_123".to_string(),
                            premium_access_addon: false,
                            billing_address: BillingAddress::default(),
                        },
                        secrets_manager: None,
                        pam: no_pam_seats(),
                        coupons: vec![],
                        trial_length: None,
                        skip_trial: false,
                    }),
                },
            )
            .await
            .unwrap();

        assert_eq!(response.organization_id, OrganizationId::new(org_id));
    }

    #[tokio::test]
    async fn provider_client_wraps_org_key_to_provider_key_and_posts_to_clients_endpoint() {
        let provider_id = ProviderId::new_v4();
        let client = make_client(ApiClient::new_mocked(move |mock| {
            mock.provider_clients_api
                .expect_create()
                .withf(move |id, model| {
                    let model = model.as_ref().unwrap();
                    *id == uuid::Uuid::from(provider_id)
                        && model.owner_email == "owner@example.com"
                        && model.seats == Some(10)
                })
                .returning(move |_id, _model| Ok(()))
                .once();
        }));
        {
            let mut ctx = client.key_store.context_mut();
            let provider_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
            #[allow(deprecated)]
            ctx.set_symmetric_key(SymmetricKeySlotId::Provider(provider_id), provider_key)
                .unwrap();
        }

        let response = client
            .create_organization(
                "Default".to_string(),
                CreateOrganizationRequest {
                    name: "Acme".to_string(),
                    business_name: None,
                    billing_email: "acme@example.com".to_string(),
                    plan_type: Some(PLAN_TYPE_ENTERPRISE_ANNUALLY),
                    initiation_path: None,
                    kind: Kind::ProviderClient(ProviderClientDetails {
                        seats: 10,
                        provider: ProviderCreateDetails {
                            provider_id,
                            client_owner_email: "owner@example.com".to_string(),
                        },
                    }),
                },
            )
            .await
            .unwrap();

        assert_eq!(
            response.organization_id,
            OrganizationId::new(uuid::Uuid::nil())
        );
    }

    #[tokio::test]
    async fn upgrade_from_premium_posts_to_upgrade_and_returns_the_organization_id() {
        let org_id = uuid::Uuid::new_v4();
        let client = make_client(ApiClient::new_mocked(move |mock| {
            mock.account_billing_v_next_api
                .expect_upgrade_premium_to_organization()
                .withf(|model| {
                    let model = model.as_ref().unwrap();
                    model.organization_name == "Acme"
                        && model.billing_address.country == "US"
                        && model.billing_address.postal_code == "12345"
                        && model.target_product_tier_type
                            == bitwarden_api_api::models::ProductTierType::Enterprise
                })
                .returning(move |_| {
                    Ok(
                        bitwarden_api_api::models::UpgradePremiumToOrganizationResponseModel {
                            organization_id: Some(org_id),
                        },
                    )
                })
                .once();
        }));

        let response = client
            .create_organization(
                "Default".to_string(),
                CreateOrganizationRequest {
                    name: "Acme".to_string(),
                    business_name: None,
                    billing_email: "acme@example.com".to_string(),
                    plan_type: Some(PLAN_TYPE_ENTERPRISE_ANNUALLY),
                    initiation_path: None,
                    kind: Kind::UpgradeFromPremium(UpgradeFromPremiumDetails {
                        target_product_tier_type: PRODUCT_TIER_ENTERPRISE,
                        billing_address: BillingAddress {
                            country: Some("US".to_string()),
                            postal_code: Some("12345".to_string()),
                            ..Default::default()
                        },
                    }),
                },
            )
            .await
            .unwrap();

        assert_eq!(response.organization_id, OrganizationId::new(org_id));
    }

    #[tokio::test]
    async fn pam_details_are_sent_to_the_server() {
        let org_id = uuid::Uuid::new_v4();
        let client = make_client(ApiClient::new_mocked(move |mock| {
            mock.organizations_api
                .expect_create_without_payment()
                .withf(|model| {
                    let model = model.as_ref().unwrap();
                    model.use_privileged_controls == Some(true) && model.pam_seats == Some(5)
                })
                .returning(move |_| {
                    Ok(OrganizationResponseModel {
                        id: Some(org_id),
                        ..Default::default()
                    })
                })
                .once();
        }));

        let response = client
            .create_organization(
                "Default".to_string(),
                CreateOrganizationRequest {
                    name: "Acme".to_string(),
                    business_name: None,
                    billing_email: "acme@example.com".to_string(),
                    plan_type: Some(PLAN_TYPE_FREE),
                    initiation_path: None,
                    kind: Kind::Free(FreeDetails {
                        secrets_manager: None,
                        pam: Some(PamDetails { pam_seats: 5 }),
                    }),
                },
            )
            .await
            .unwrap();

        assert_eq!(response.organization_id, OrganizationId::new(org_id));
    }

    #[tokio::test]
    async fn api_failure_maps_to_api_error() {
        let client = make_client(ApiClient::new_mocked(|mock| {
            mock.organizations_api
                .expect_create_without_payment()
                .returning(|_| Err(ApiError::Io(std::io::Error::other("boom"))))
                .once();
        }));

        let result = client
            .create_organization(
                "Default".to_string(),
                CreateOrganizationRequest {
                    name: "Acme".to_string(),
                    business_name: None,
                    billing_email: "acme@example.com".to_string(),
                    plan_type: Some(PLAN_TYPE_FREE),
                    initiation_path: None,
                    kind: Kind::Free(FreeDetails {
                        secrets_manager: None,
                        pam: no_pam_seats(),
                    }),
                },
            )
            .await;

        assert!(matches!(result, Err(CreateOrganizationError::Api(_))));
    }
}
