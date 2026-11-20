use bitwarden_api_api::models::{
    AssertionResponse, AttestationResponse, AuthenticationExtensionsClientOutputs,
    AuthenticatorAssertionRawResponse, AuthenticatorAttestationRawResponse, AuthenticatorTransport,
    CredentialCreateOptions, PublicKeyCredentialType, SecretVerificationRequestModel,
    UserVerificationRequirement, WebAuthnCredentialCreateOptionsResponseModel,
    WebAuthnLoginCredentialCreateRequestModel,
};
use bitwarden_core::{
    Client, key_management::SymmetricKeySlotId, mobile::KdfClient,
    platform::SecretVerificationRequest,
};
use bitwarden_crypto::{HashPurpose, Kdf, RotateableKeySet};
use bitwarden_encoding::{B64, B64Url};
use chrono::{DateTime, Utc};
use coset::{CborSerializable, CoseKey};
use passkey::{
    authenticator::{
        DiscoverabilitySupport, StoreInfo, UiHint, UserCheck, extensions::HmacSecretConfig,
    },
    types::{
        CredentialExtensions, Passkey, StoredHmacSecret,
        crypto::sha256,
        ctap2::{self, Ctap2Code, Ctap2Error, StatusCode, VendorError, make_credential::Options},
    },
};
use reqwest::Url;

use crate::{
    GetAssertionRequest, MakeCredentialResult, PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    types::{
        GetAssertionExtensionsInput, GetAssertionExtensionsOutput, GetAssertionPrfInput,
        MakeCredentialExtensionsInput, MakeCredentialPrfInput, PrfInputValues,
        PublicKeyCredentialDescriptor, PublicKeyCredentialParameters, UV, WebAuthnEntityError,
    },
};

/// A FIDO authenticator that uses the device auth key for its key material.
pub struct DeviceAuthKeyAuthenticator<'a> {
    /// The SDK client.
    pub client: &'a Client,

    /// Callbacks for storing and retrieving the device auth key during FIDO operations.
    pub store: &'a mut dyn DeviceAuthKeyStore,
}

impl DeviceAuthKeyAuthenticator<'_> {
    /// Create a device auth key by registering an unlock passkey and PRF keyset with the server.
    /// The passkey private key and metadata will be stored on the device using the provided trait
    /// implementation. Returns the PRF key set that was registered.
    pub async fn create_device_auth_key(
        &mut self,
        client_name: String,
        web_vault_url: String,
        // TODO(PM-22681): We should define an enum to accept all the different
        // SecretVerificationRequest input methods that the server can accept,
        // and have a centralized place where the secret verification can be
        // derived from the input.
        //
        // For now, we are hard-coding master password hash and OTP.
        // When PM-22681 is complete, we can use that implementation here as a
        // breaking change.
        email: String,
        secret_verification_request: SecretVerificationRequest,
        kdf_params: Kdf,
    ) -> Result<RotateableKeySet, DeviceAuthKeyError> {
        // Derive secret verification request
        let config = self.client.internal.get_api_configurations();
        let api_client = &config.api_client;

        // Request WebAuthn credential creation options
        let secret_verification_request_model = build_secret_verification_request(
            &secret_verification_request,
            email,
            kdf_params,
            &self.client.kdf(),
        )
        .await?;
        let options_response = api_client
            .web_authn_api()
            .attestation_options(Some(secret_verification_request_model))
            .await
            .map_err(|err| {
                tracing::error!(%err, "Failed to retrieve attestation options");
                DeviceAuthKeyError::RetrieveRegistrationOptionsFailure
            })?;
        let WebAuthnCredentialCreateOptionsResponseModel { options, token, .. } = options_response;

        // Convert creation options
        let (default_rp_id, origin) = rp_id_and_origin(&web_vault_url)?;
        let (request, client_data_json) = convert_creation_options(options.as_ref(), default_rp_id, origin).map_err(|err| {
            tracing::error!(%err, ?options, "Received invalid WebAuthn attestation options from server");
            DeviceAuthKeyError::RetrieveRegistrationOptionsFailure
        })?;

        // Extract user/RP data from request before make_credential consumes it.
        let rp_id = request.rp.id.clone();
        let user_handle = request.user.id.to_vec();
        let user_name = request.user.name.clone();
        let user_display_name = request.user.display_name.clone();

        // Create credential with passkey-rs, store record on device with given trait implementation
        let store = DeviceAuthKeyStoreInternal::new(self.store);
        let ui = DeviceAuthKeyUiInternal {};
        let mut authenticator =
            passkey::authenticator::Authenticator::new(super::AAGUID, store, ui)
                .hmac_secret(HmacSecretConfig::new_with_uv_only().enable_on_make_credential());
        let response = authenticator
            .make_credential(request)
            .await
            .map_err(|status_code| {
                tracing::error!(?status_code, "Failed to make FIDO credential");
                if let StatusCode::Ctap2(Ctap2Code::Known(Ctap2Error::CredentialExcluded)) =
                    status_code
                {
                    DeviceAuthKeyError::CredentialExcluded
                } else {
                    DeviceAuthKeyError::AuthenticatorFailure
                }
            })?;

        // Convert response
        let result: MakeCredentialResult = response
            .try_into()
            .map_err(|_| DeviceAuthKeyError::AuthenticatorFailure)?;

        // Make PRF key set
        let prf_result = result
            .extensions
            .prf
            .and_then(|prf| prf.results)
            .ok_or_else(|| {
                tracing::error!("No PRF output received from authenticator response");
                DeviceAuthKeyError::PrfFailure
            })?
            .first;
        let prf_key =
            bitwarden_crypto::derive_symmetric_key_from_prf(&prf_result).map_err(|err| {
                tracing::error!(?err, "Failed to derive symmetric key from PRF output");
                DeviceAuthKeyError::PrfFailure
            })?;
        let key_set = {
            let ctx = self.client.internal.get_key_store().context();
            RotateableKeySet::new(&ctx, &prf_key, SymmetricKeySlotId::User).map_err(|err| {
                tracing::error!(%err, "Failed to gen/Conerate rotateable key set from PRF output");
                DeviceAuthKeyError::PrfFailure
            })?
        };

        // Send registration request to server
        let credential_id = result.credential_id.clone();
        let create_request = WebAuthnLoginCredentialCreateRequestModel {
            device_response: Box::new(AuthenticatorAttestationRawResponse {
                // The WebAuthn `id` is the base64url encoding of the raw credential ID.
                id: bitwarden_encoding::B64Url::from(result.credential_id.as_slice()).to_string(),
                raw_id: result.credential_id,
                r#type: PublicKeyCredentialType::PublicKey,
                response: Box::new(AttestationResponse {
                    attestation_object: Some(result.attestation_object),
                    client_data_json: Some(client_data_json.into_bytes()),
                    // The device auth key lives in device-bound storage, so the credential is
                    // only reachable through the platform authenticator.
                    transports: vec![AuthenticatorTransport::Internal],
                }),
                // Deprecated alias for client_extension_results. Both deserialize into the same
                // value with no precedence, so only client_extension_results is populated.
                extensions: None,
                // The authenticator's PRF output is consumed locally for the rotateable key set,
                // and PRF support is reported through supports_prf, so the server needs no client
                // extension outputs here.
                client_extension_results: Box::new(AuthenticationExtensionsClientOutputs::new()),
            }),
            name: client_name,
            token,
            supports_prf: true,
            encrypted_user_key: Some(key_set.encapsulated_downstream_key.to_string()),
            encrypted_public_key: Some(key_set.encrypted_encapsulation_key.to_string()),
            encrypted_private_key: Some(key_set.encrypted_decapsulation_key.to_string()),
        };
        let server_response = api_client
            .web_authn_api()
            .post(Some(create_request))
            .await
            .map_err(|err| {
                tracing::error!(%err, "Failed to submit passkey and PRF key set to server");
                DeviceAuthKeyError::SubmitRegistrationFailure
            })?;
        let record_identifier = server_response
            .id
            .ok_or(DeviceAuthKeyError::SubmitRegistrationFailure)?;

        // Save metadata now that we have the server-assigned record identifier
        let metadata = DeviceAuthKeyMetadata {
            record_identifier,
            creation_date: chrono::offset::Utc::now(),
            credential_id,
            rp_id,
            user_handle,
            user_name,
            user_display_name,
        };
        self.store.create_metadata(metadata).await.map_err(|err| {
            tracing::error!(%err, "Failed to save device auth key metadata");
            err
        })?;
        Ok(key_set)
    }

    /// Assert the device auth key for a `webauthn` grant login. Gets the assertion options from
    /// the server and returns the token request values and the PRF output.
    pub async fn assert_device_auth_key_for_login(
        &mut self,
        web_vault_url: String,
    ) -> Result<DeviceAuthKeyLoginAssertion, DeviceAuthKeyError> {
        let (default_rp_id, origin) = rp_id_and_origin(&web_vault_url)?;
        let config = self.client.internal.get_api_configurations();
        let options_response = config
            .identity_client
            .accounts_api()
            .get_web_authn_login_assertion_options()
            .await
            .map_err(|err| {
                tracing::error!(%err, "Failed to retrieve assertion options");
                DeviceAuthKeyError::RetrieveAssertionOptionsFailure
            })?;
        let options = options_response.options;
        let challenge = options
            .challenge
            .ok_or(DeviceAuthKeyError::RetrieveAssertionOptionsFailure)?;
        let client_data_json = client_data_json("webauthn.get", &challenge, &origin);
        // Same PRF input rule as creation.
        let prf_input = prf_input_or_default(
            options
                .extensions
                .as_ref()
                .and_then(|e| e.prf.as_ref())
                .and_then(|prf| prf.eval.as_ref())
                .and_then(|eval| eval.first.clone()),
        );
        let rp_id = options.rp_id.unwrap_or(default_rp_id);
        let (assertion, prf_output) = self
            .assert_with_prf(
                rp_id,
                sha256(client_data_json.as_bytes()).to_vec(),
                prf_input,
            )
            .await?;

        let device_response = AuthenticatorAssertionRawResponse {
            id: B64Url::from(assertion.credential_id.as_slice()).to_string(),
            raw_id: assertion.credential_id,
            response: Some(Box::new(AssertionResponse {
                authenticator_data: Some(assertion.authenticator_data),
                signature: Some(assertion.signature),
                client_data_json: Some(client_data_json.into_bytes()),
                user_handle: Some(assertion.user_handle),
            })),
            r#type: PublicKeyCredentialType::PublicKey,
            extensions: None,
            client_extension_results: Box::new(AuthenticationExtensionsClientOutputs::new()),
        };
        let device_response =
            serde_json::to_string(&device_response).map_err(|_| DeviceAuthKeyError::Conversion)?;
        Ok(DeviceAuthKeyLoginAssertion {
            token: options_response.token,
            device_response,
            prf_output,
        })
    }

    /// Get the PRF output of the device auth key, to unlock the vault on this device. Uses the
    /// default PRF input, so it matches a key set made without a server PRF input.
    pub async fn get_prf_output(&mut self) -> Result<B64, DeviceAuthKeyError> {
        let metadata = self
            .store
            .get_metadata()
            .await?
            .ok_or(DeviceAuthKeyError::MissingDeviceAuthKey)?;
        // No relying party verifies this assertion, so the client data hash is a placeholder.
        let (_, prf_output) = self
            .assert_with_prf(metadata.rp_id, vec![0; 32], prf_input_or_default(None))
            .await?;
        Ok(prf_output)
    }

    /// Assert the device auth key with a PRF input. Returns the assertion and the PRF output.
    async fn assert_with_prf(
        &mut self,
        rp_id: String,
        client_data_hash: Vec<u8>,
        prf_input: Vec<u8>,
    ) -> Result<(DeviceAuthKeyGetAssertionResult, B64), DeviceAuthKeyError> {
        let assertion = self
            .assert_device_auth_key(GetAssertionRequest {
                rp_id,
                client_data_hash,
                allow_list: None,
                options: crate::types::Options {
                    rk: false,
                    uv: UV::Required,
                },
                extensions: Some(GetAssertionExtensionsInput {
                    prf: Some(GetAssertionPrfInput {
                        eval: Some(PrfInputValues {
                            first: prf_input,
                            second: None,
                        }),
                        eval_by_credential: None,
                    }),
                }),
            })
            .await?;
        let prf_output = assertion
            .extensions
            .prf
            .as_ref()
            .map(|prf| B64::from(prf.results.first.as_slice()))
            .ok_or(DeviceAuthKeyError::PrfFailure)?;
        Ok((assertion, prf_output))
    }

    /// Satisfy the given FIDO assertion `request` using the device auth key.
    /// The device auth key will be looked up from the
    /// [DeviceAuthKeyAuthenticator::store] provided in the initializer.
    pub async fn assert_device_auth_key(
        &mut self,
        request: GetAssertionRequest,
    ) -> Result<DeviceAuthKeyGetAssertionResult, DeviceAuthKeyError> {
        // Convert request
        let request = ctap2::get_assertion::Request {
            rp_id: request.rp_id,
            client_data_hash: request.client_data_hash.into(),
            allow_list: request
                .allow_list
                .map(|l| {
                    l.into_iter()
                        .map(TryInto::try_into)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|_| DeviceAuthKeyError::InvalidPublicKeyCredentialDescriptor)
                })
                .transpose()?,
            extensions: request
                .extensions
                .map(passkey::types::ctap2::get_assertion::ExtensionInputs::from),
            options: passkey::types::ctap2::make_credential::Options {
                rk: request.options.rk,
                up: true,
                uv: match request.options.uv {
                    UV::Discouraged => false,
                    UV::Preferred => true,
                    UV::Required => true,
                },
            },
            pin_auth: None,
            pin_protocol: None,
        };

        // Only use the requested credential ID if exactly one is specified.
        let requested_cred_id = if let Some([cred]) = request.allow_list.as_deref() {
            Some(cred.id.to_vec())
        } else {
            None
        };

        // Get signature
        let store = DeviceAuthKeyStoreInternal::new(self.store);
        let ui = DeviceAuthKeyUiInternal {};
        let mut authenticator =
            passkey::authenticator::Authenticator::new(super::AAGUID, store, ui)
                .hmac_secret(HmacSecretConfig::new_with_uv_only().enable_on_make_credential());
        let response = match authenticator.get_assertion(request).await {
            Ok(response) => response,
            Err(status_code) => {
                tracing::error!(?status_code, "Authenticator failed to assert credential");
                return Err(authenticator
                    .store()
                    .take_record_error()
                    .unwrap_or(DeviceAuthKeyError::AuthenticatorFailure));
            }
        };

        // Convert response
        let authenticator_data = response.auth_data.to_vec();
        // Credential ID may be omitted if there is only one credential ID
        // specified in the allow list. We currently use device auth keys exclusively as a
        // discoverable credentials, which means the allow list will always be
        // empty and the credential ID should always be returned, but if that
        // changes, we should attempt to read it from the allow list, just in case.
        let credential_id = response
            .credential
            .map(|cred| cred.id.to_vec())
            .or(requested_cred_id)
            .ok_or(DeviceAuthKeyError::MissingCredentialId)?;
        let extensions: GetAssertionExtensionsOutput = response.unsigned_extension_outputs.into();
        let user_handle = response
            .user
            .map(|u| u.id.to_vec())
            .ok_or(DeviceAuthKeyError::MissingUserHandle)?;
        Ok(DeviceAuthKeyGetAssertionResult {
            credential_id,
            authenticator_data,
            signature: response.signature.to_vec(),
            user_handle,
            extensions,
        })
    }

    /// Delete the device auth key from the device and unregister it from the server.
    pub async fn unregister_device_auth_key(
        &mut self,
        email: String,
        secret_verification_request: SecretVerificationRequest,
        kdf_params: Kdf,
    ) -> Result<(), DeviceAuthKeyError> {
        // Retrieve metadata before we delete it
        let metadata = self
            .store
            .get_metadata()
            .await?
            .ok_or(DeviceAuthKeyError::MissingDeviceAuthKey)?;

        self.store.delete_record_and_metadata().await?;

        let record_id = metadata
            .record_identifier
            .parse::<uuid::Uuid>()
            .map_err(|err| {
                tracing::error!(%err, "Failed to parse record identifier as UUID");
                DeviceAuthKeyError::InvalidRecordIdentifier
            })?;

        // Attempt to unregister the device auth key from the server.
        let config = self.client.internal.get_api_configurations();
        let api_client = &config.api_client;
        let secret_verification_request_model = build_secret_verification_request(
            &secret_verification_request,
            email,
            kdf_params,
            &self.client.kdf(),
        )
        .await?;
        api_client
            .web_authn_api()
            .delete(record_id, Some(secret_verification_request_model))
            .await
            .map_err(|err| {
                tracing::error!(%err, "Failed to unregister device auth key from server");
                DeviceAuthKeyError::UnregisterFailure
            })?;

        Ok(())
    }
}

async fn build_secret_verification_request(
    input: &SecretVerificationRequest,
    email: String,
    kdf_params: Kdf,
    kdf_client: &KdfClient,
) -> Result<SecretVerificationRequestModel, DeviceAuthKeyError> {
    let master_password_hash = if let Some(master_password) = &input.master_password {
        Some(
            kdf_client
                .hash_password(
                    email,
                    master_password.to_string(),
                    kdf_params,
                    HashPurpose::ServerAuthorization,
                )
                .await
                .map_err(|_| DeviceAuthKeyError::MasterPasswordHash)?
                .to_string(),
        )
    } else {
        None
    };

    Ok(SecretVerificationRequestModel {
        master_password_hash,
        otp: input.otp.clone(),
        auth_request_access_code: None,
        secret: None,
    })
}

/// The server's PRF input, else the one that Bitwarden clients use to log in with a passkey.
fn prf_input_or_default(server_input: Option<Vec<u8>>) -> Vec<u8> {
    server_input.unwrap_or_else(|| sha256("passwordless-login".as_bytes()).to_vec())
}

/// The `clientDataJSON` of a WebAuthn ceremony of the given type.
fn client_data_json(kind: &str, challenge: &[u8], origin: &str) -> String {
    format!(
        r#"{{"type":"{}","challenge":"{}","origin":"{}","crossOrigin":false}}"#,
        kind,
        B64Url::from(challenge),
        origin
    )
}

/// The default RP ID (the host) and the origin of the web vault URL.
fn rp_id_and_origin(web_vault_url: &str) -> Result<(String, String), DeviceAuthKeyError> {
    let url = Url::parse(web_vault_url).map_err(|_| DeviceAuthKeyError::InvalidWebVaultUrl)?;
    let rp_id = url
        .host()
        .map(|host| host.to_string())
        .ok_or(DeviceAuthKeyError::InvalidWebVaultUrl)?;
    Ok((rp_id, url.origin().ascii_serialization()))
}

/// Create a CTAP2 makeCredential request and clientDataJSON from the WebAuthn credential
/// attestations options received from the server. Generates clientDataJSON from given origin and
/// challenge, and injects the default RP ID if it's missing.
fn convert_creation_options(
    options: &CredentialCreateOptions,
    default_rp_id: String,
    origin: String,
) -> Result<(passkey::types::ctap2::make_credential::Request, String), WebAuthnEntityError> {
    let mut missing_fields = Vec::with_capacity(0);
    if options.challenge.is_none() {
        missing_fields.push("challenge".to_string());
    }
    if options.pub_key_cred_params.is_none() {
        missing_fields.push("pubKeyCredParams".to_string());
    }
    if !missing_fields.is_empty() {
        return Err(WebAuthnEntityError::MissingRequiredFields(missing_fields));
    }

    let CredentialCreateOptions {
        rp,
        user,
        challenge: Some(challenge),
        pub_key_cred_params: Some(pub_key_cred_params),
        authenticator_selection,
        exclude_credentials,
        extensions,
        ..
    } = options
    else {
        // these required fields should be manually checked above, so this shouldn't be reached.
        unreachable!("Missing required fields on options");
    };

    let client_data_json = client_data_json("webauthn.create", challenge, &origin);
    let client_data_hash = passkey::types::crypto::sha256(client_data_json.as_bytes()).to_vec();

    // Inject default RP ID
    let mut rp = rp.clone();
    rp.id.get_or_insert(default_rp_id);
    let rp = TryInto::<PublicKeyCredentialRpEntity>::try_into(rp.as_ref())?.into();

    let user_entity = TryInto::<PublicKeyCredentialUserEntity>::try_into(user.as_ref())?.into();
    let pub_key_cred_params = pub_key_cred_params
        .iter()
        .map(|p| {
            PublicKeyCredentialParameters::try_from(p).and_then(|ours| {
                passkey::types::webauthn::PublicKeyCredentialParameters::try_from(ours)
            })
        })
        .collect::<Result<Vec<passkey::types::webauthn::PublicKeyCredentialParameters>, _>>()?;
    let exclude_list = exclude_credentials
        .as_ref()
        .map(|l| {
            l.iter()
                .map(|c| {
                    let descriptor = PublicKeyCredentialDescriptor::try_from(c);

                    descriptor.and_then(|c| c.try_into().map_err(WebAuthnEntityError::from))
                })
                .collect()
        })
        .transpose()?;
    let authenticator_options = authenticator_selection
        .as_ref()
        .map(|o| Options {
            // TODO: Consider deriving `rk` from `resident_key` instead. Fido2NetLib marks
            // `RequireResidentKey` obsolete in favor of `ResidentKey`. The device auth key must
            // be discoverable, so options that carry only `residentKey` would leave `rk` false.
            rk: o.require_resident_key.unwrap_or_default(),
            uv: !matches!(
                o.user_verification,
                Some(UserVerificationRequirement::Discouraged)
            ),
            up: true,
        })
        .unwrap_or_else(|| Options {
            rk: false,
            uv: true,
            up: true,
        });

    // Use the server's PRF input, else the Bitwarden login salt. Apply the WebAuthn PRF domain
    // separation like an assertion does, so a later assertion with the same input gives the same
    // output.
    let prf_first = prf_input_or_default(
        extensions
            .as_ref()
            .and_then(|e| e.prf.as_ref())
            .and_then(|prf| prf.eval.as_ref())
            .and_then(|eval| eval.first.clone()),
    );
    let request = passkey::types::ctap2::make_credential::Request {
        client_data_hash: client_data_hash.into(),
        rp,
        user: user_entity,
        pub_key_cred_params,
        exclude_list,
        options: authenticator_options,
        extensions: Some(
            MakeCredentialExtensionsInput {
                prf: Some(MakeCredentialPrfInput {
                    eval: Some(PrfInputValues {
                        first: prf_first,
                        second: None,
                    }),
                }),
            }
            .into(),
        ),
        pin_auth: None,
        pin_protocol: None,
    };
    Ok((request, client_data_json))
}

/// Fields corresponding to a WebAuthn [PublicKeyCredential][pub-key-cred]
/// with an [AuthenticatorAssertionResponse][authenticator-assertion-response].
///
/// Similar to [GetAssertionResult][crate::GetAssertionResult], but without the reference to the
/// vault cipher.
///
/// [pub-key-cred]: https://www.w3.org/TR/webauthn-3/#publickeycredential
/// [authenticator-assertion-response]: https://www.w3.org/TR/webauthn-3/#authenticatorassertionresponse
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct DeviceAuthKeyGetAssertionResult {
    /// ID for this credential, corresponding to [`PublicKeyCredential.rawId`][raw-id].
    ///
    /// [raw-id]: https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-rawid
    pub credential_id: Vec<u8>,

    /// The authenticator data from the authenticator response.
    pub authenticator_data: Vec<u8>,

    /// Signature over the authenticator data.
    pub signature: Vec<u8>,

    /// The user handle returned from the authenticator.
    pub user_handle: Vec<u8>,

    /// Mix of CTAP unsigned extension output and WebAuthn client extension output.
    /// Signed extensions can be retrieved from authenticator data.
    pub extensions: GetAssertionExtensionsOutput,
}

/// The private key material for the device auth key.
/// This should be stored separately from the metadata and gated behind
/// user-verifying access control.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct DeviceAuthKeyRecord {
    /// Credential ID for the WebAuthn credential.
    pub credential_id: Vec<u8>,

    /// Private key material, formatted as a COSE key.
    pub key: Vec<u8>,

    /// RP ID of the WebAuthn credential.
    pub rp_id: String,

    /// User ID for the WebAuthn credential.
    pub user_id: Vec<u8>,

    /// WebAuthn counter for the credential.
    pub counter: Option<u32>,

    /// HMAC Secret seed, which can also be used in WebAuthn PRF extension.
    pub hmac_secret: Vec<u8>,
}

impl TryFrom<Passkey> for DeviceAuthKeyRecord {
    type Error = DeviceAuthKeyError;
    fn try_from(value: Passkey) -> Result<Self, Self::Error> {
        let credential_id = value.credential_id.to_vec();
        let key = value.key.to_vec().map_err(|err| {
            tracing::error!(%err, "Failed to serialize COSE key to bytes.");
            DeviceAuthKeyError::InvalidCoseKey
        })?;
        let user_id = value
            .user_handle
            .ok_or(DeviceAuthKeyError::MissingUserHandle)?
            .to_vec();
        let hmac_secret = value
            .extensions
            .hmac_secret
            .as_ref()
            .ok_or(DeviceAuthKeyError::MissingHmacSecret)?
            .cred_with_uv
            .clone();
        Ok(DeviceAuthKeyRecord {
            credential_id,
            key,
            rp_id: value.rp_id,
            user_id,
            counter: value.counter,
            hmac_secret,
        })
    }
}

impl TryFrom<DeviceAuthKeyRecord> for Passkey {
    type Error = DeviceAuthKeyError;
    fn try_from(value: DeviceAuthKeyRecord) -> Result<Self, Self::Error> {
        Ok(Passkey {
            credential_id: value.credential_id.into(),
            key: CoseKey::from_slice(&value.key).map_err(|err| {
                tracing::error!(%err, "Failed to deserialize COSE key from bytes");
                DeviceAuthKeyError::InvalidCoseKey
            })?,
            rp_id: value.rp_id,
            user_handle: Some(value.user_id.into()),
            counter: value.counter,
            extensions: CredentialExtensions {
                hmac_secret: Some(StoredHmacSecret {
                    cred_with_uv: value.hmac_secret,
                    cred_without_uv: None,
                }),
            },
        })
    }
}

/// The metadata for the device auth key useful for looking up whether the
/// authenticator can satisfy a given request before invoking user-verifying
/// access control.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct DeviceAuthKeyMetadata {
    /// A unique identifier for the device auth key passkey.
    /// This can be used as a unique identifier in OS autofill stores.
    pub record_identifier: String,

    /// Date the device auth key was created.
    pub creation_date: DateTime<Utc>,

    /// FIDO credential ID for the device auth key.
    pub credential_id: Vec<u8>,

    /// WebAuthn RP ID for the device auth key.
    pub rp_id: String,

    /// The login or username for user.
    ///
    /// Corresponds to the [user.name] in the original WebAuthn request that created the
    /// credential.
    pub user_name: String,

    /// The ID for the user.
    ///
    /// Corresponds to the [user.id] in the original WebAuthn request that created the credential.
    pub user_handle: Vec<u8>,

    /// The display name for the user
    ///
    /// Corresponds to the [user.displayName] in the original WebAuthn request that created the
    /// credential.
    pub user_display_name: String,
}

/// The values of a `webauthn` grant token request, and the PRF output of the device auth key.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct DeviceAuthKeyLoginAssertion {
    /// The `token` value from the assertion options.
    pub token: String,
    /// The `deviceResponse` value: an `AuthenticatorAssertionRawResponse` as JSON.
    pub device_response: String,
    /// The PRF output that opens the PRF key set of the device auth key.
    pub prf_output: B64,
}

/// Errors related to processing the device auth key.
#[derive(Debug, thiserror::Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error), uniffi(flat_error))]
pub enum DeviceAuthKeyError {
    /// Authenticator failed to produce a valid response.
    #[error("The authenticator failed to produce a valid response")]
    AuthenticatorFailure,

    /// Failed to convert between Rust types.
    #[error("Failed to convert between Rust types")]
    Conversion,

    /// Credential excluded.
    #[error("The existing device auth key is already registered on the server.")]
    CredentialExcluded,

    /// The record identifier stored in metadata is not a valid UUID.
    #[error("The record identifier is not a valid UUID")]
    InvalidRecordIdentifier,

    /// Invalid Web Vault URL specified.
    #[error("Invalid Web Vault URL specified")]
    InvalidWebVaultUrl,

    /// No device auth key exists on this device.
    #[error("No device auth key exists on this device")]
    MissingDeviceAuthKey,

    /// Failed to unregister device auth key from server.
    #[error("Failed to unregister device auth key from server")]
    UnregisterFailure,

    /// Failed to de-/serialize COSE key data.
    #[error("Failed to de-/serialize COSE key data")]
    InvalidCoseKey,

    /// An invalid public key credential descriptor was passed in the allow list.
    #[error("An invalid public key credential descriptor was passed in the allow list")]
    InvalidPublicKeyCredentialDescriptor,

    /// A master password hash could not be generated for the given master password.
    #[error("A master password hash could not be generated for the given master password")]
    MasterPasswordHash,

    /// Credential ID was not returned in the response and was not passed in the request.
    #[error(
        "No credential ID was returned in the response nor was a single credential ID passed in the request"
    )]
    MissingCredentialId,

    /// No HMAC secret was returned with the credential.
    #[error("No HMAC secret was returned with the credential")]
    MissingHmacSecret,

    /// User handle was not returned in the response.
    #[error("User handle was not returned in the response")]
    MissingUserHandle,

    /// Feature is not yet implemented.
    #[error("Feature is not yet implemented")]
    NotImplemented,

    /// Failed to retrieve the registration options from the server.
    #[error("Failed to retrieve the registration options from the server")]
    RetrieveRegistrationOptionsFailure,

    /// Failed to retrieve the assertion options from the server.
    #[error("Failed to retrieve the assertion options from the server")]
    RetrieveAssertionOptionsFailure,

    /// Failed to generate rotateable key set from PRF output.
    #[error("Failed to generate rotateable key set from PRF output")]
    PrfFailure,

    /// Failed to submit registration request to the server.
    #[error("Failed to submit registration request to the server")]
    SubmitRegistrationFailure,

    /// User cancelled the operation.
    #[error("User cancelled the operation")]
    UserCancelled,

    /// An unknown error occurred.
    #[error("An unknown error occurred")]
    Unknown {
        /// Reason for the error.
        reason: String,
    },
}

// Need to implement this From<> impl in order to handle unexpected callback errors.  See the
// following page in the Uniffi user guide:
// <https://mozilla.github.io/uniffi-rs/foreign_traits.html#error-handling>
#[cfg(feature = "uniffi")]
impl From<uniffi::UnexpectedUniFFICallbackError> for DeviceAuthKeyError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Unknown { reason: e.reason }
    }
}

/// A trait used to interact with the device auth key data on the device.
#[async_trait::async_trait]
pub trait DeviceAuthKeyStore: Send + Sync {
    /// Create a record (private key material).
    ///
    /// The record should be stored in device-bound storage and protected with user-verifying access
    /// controls.
    async fn create_record(
        &mut self,
        record: DeviceAuthKeyRecord,
    ) -> Result<(), DeviceAuthKeyError>;

    /// Create metadata for the device auth key.
    ///
    /// The metadata should be stored separately without access controls that require UI.
    async fn create_metadata(
        &mut self,
        metadata: DeviceAuthKeyMetadata,
    ) -> Result<(), DeviceAuthKeyError>;

    /// Retrieve the device auth key metadata.
    async fn get_metadata(&self) -> Result<Option<DeviceAuthKeyMetadata>, DeviceAuthKeyError>;

    /// Retrieve the device auth key private key material.
    async fn get_record(&self) -> Result<Option<DeviceAuthKeyRecord>, DeviceAuthKeyError>;

    /// Delete the device auth key (both the record and metadata) from the device.
    async fn delete_record_and_metadata(&mut self) -> Result<(), DeviceAuthKeyError>;
}

struct DeviceAuthKeyStoreInternal<'a> {
    store: &'a mut dyn DeviceAuthKeyStore,
    /// The error of a failed record read. passkey-rs turns it into a status code, so it is kept
    /// here and returned instead, for example [DeviceAuthKeyError::UserCancelled].
    record_error: std::sync::Mutex<Option<DeviceAuthKeyError>>,
}

impl<'a> DeviceAuthKeyStoreInternal<'a> {
    fn new(store: &'a mut dyn DeviceAuthKeyStore) -> Self {
        Self {
            store,
            record_error: std::sync::Mutex::new(None),
        }
    }

    fn take_record_error(&self) -> Option<DeviceAuthKeyError> {
        self.record_error.lock().ok()?.take()
    }
}

#[async_trait::async_trait]
impl passkey::authenticator::CredentialStore for DeviceAuthKeyStoreInternal<'_> {
    type PasskeyItem = DeviceAuthKeyRecord;

    async fn find_credentials(
        &self,
        _ids: Option<&[passkey::types::webauthn::PublicKeyCredentialDescriptor]>,
        _rp_id: &str,
        _user_handle: Option<&[u8]>,
    ) -> Result<Vec<Self::PasskeyItem>, StatusCode> {
        match self.store.get_record().await {
            Ok(Some(key)) => Ok(vec![key]),
            Ok(None) => return Ok(vec![]),
            Err(err) => {
                if let Ok(mut record_error) = self.record_error.lock() {
                    *record_error = Some(err);
                }
                Err(VendorError::try_from(0xf0)
                    .expect("valid vendor error")
                    .into())
            }
        }
    }

    async fn save_credential(
        &mut self,
        cred: Passkey,
        _user: passkey::types::ctap2::make_credential::PublicKeyCredentialUserEntity,
        _rp: passkey::types::ctap2::make_credential::PublicKeyCredentialRpEntity,
        _options: passkey::types::ctap2::get_assertion::Options,
    ) -> Result<(), StatusCode> {
        let record = cred
            .try_into()
            .map_err(|_| VendorError::try_from(0xf0).expect("valid vendor error"))?;

        self.store.create_record(record).await.map_err(|_| {
            StatusCode::from(VendorError::try_from(0xf0).expect("valid vendor error"))
        })?;
        Ok(())
    }

    async fn update_credential(&mut self, _cred: Passkey) -> Result<(), StatusCode> {
        // This is only used to update the counter, which we're not currently using.
        tracing::warn!("called update_credential() on device auth key, which is not supported");
        Err(StatusCode::Ctap2(
            VendorError::try_from(0xF3)
                .expect("valid vendor error")
                .into(),
        ))
    }

    async fn get_info(&self) -> StoreInfo {
        StoreInfo {
            discoverability: DiscoverabilitySupport::Full,
        }
    }
}

struct DeviceAuthKeyUiInternal {}

#[async_trait::async_trait]
impl passkey::authenticator::UserValidationMethod for DeviceAuthKeyUiInternal {
    type PasskeyItem = DeviceAuthKeyRecord;

    async fn check_user<'a>(
        &self,
        _hint: UiHint<'a, Self::PasskeyItem>,
        _presence: bool,
        _verification: bool,
    ) -> Result<UserCheck, Ctap2Error> {
        // The DeviceAuthKeyStore trait should store with user-verifying access
        // control, so we assume that user presence and verification has been
        // achieved.
        Ok(UserCheck {
            presence: true,
            verification: true,
        })
    }

    fn is_presence_enabled(&self) -> bool {
        true
    }

    fn is_verification_enabled(&self) -> Option<bool> {
        Some(true)
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::client::ApiConfigurations;

    use super::*;

    #[derive(Default)]
    struct MemStore {
        record: Option<DeviceAuthKeyRecord>,
        metadata: Option<DeviceAuthKeyMetadata>,
        cancel_record_read: bool,
    }

    #[async_trait::async_trait]
    impl DeviceAuthKeyStore for MemStore {
        async fn create_record(
            &mut self,
            record: DeviceAuthKeyRecord,
        ) -> Result<(), DeviceAuthKeyError> {
            self.record = Some(record);
            Ok(())
        }
        async fn create_metadata(
            &mut self,
            metadata: DeviceAuthKeyMetadata,
        ) -> Result<(), DeviceAuthKeyError> {
            self.metadata = Some(metadata);
            Ok(())
        }
        async fn get_metadata(&self) -> Result<Option<DeviceAuthKeyMetadata>, DeviceAuthKeyError> {
            Ok(self.metadata.as_ref().map(|m| DeviceAuthKeyMetadata {
                record_identifier: m.record_identifier.clone(),
                creation_date: m.creation_date,
                credential_id: m.credential_id.clone(),
                rp_id: m.rp_id.clone(),
                user_name: m.user_name.clone(),
                user_display_name: m.user_display_name.clone(),
                user_handle: m.user_handle.clone(),
            }))
        }
        async fn get_record(&self) -> Result<Option<DeviceAuthKeyRecord>, DeviceAuthKeyError> {
            if self.cancel_record_read {
                return Err(DeviceAuthKeyError::UserCancelled);
            }
            Ok(self.record.as_ref().map(|r| DeviceAuthKeyRecord {
                credential_id: r.credential_id.clone(),
                key: r.key.clone(),
                rp_id: r.rp_id.clone(),
                user_id: r.user_id.clone(),
                counter: r.counter,
                hmac_secret: r.hmac_secret.clone(),
            }))
        }
        async fn delete_record_and_metadata(&mut self) -> Result<(), DeviceAuthKeyError> {
            self.record = None;
            self.metadata = None;
            Ok(())
        }
    }

    /// Creates a device auth key in `mem` and returns the PRF output of the creation.
    async fn create_test_credential(mem: &mut MemStore) -> Vec<u8> {
        // Server-shaped attestation options without PRF extension input.
        let options: CredentialCreateOptions = serde_json::from_value(serde_json::json!({
            "rp": {"id": "localhost", "name": "Bitwarden"},
            "user": {"id": "AQIDBAUGBwg", "name": "dak@example.com", "displayName": "dak"},
            "challenge": "AAECAwQFBgcICQoLDA0ODw",
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "authenticatorSelection": {"residentKey": "required", "requireResidentKey": true, "userVerification": "required"}
        }))
        .expect("options");

        // Creation: the request builder and authenticator setup of create_device_auth_key.
        let (request, _) = convert_creation_options(
            &options,
            "localhost".to_string(),
            "https://localhost:8080".to_string(),
        )
        .expect("request");
        let store = DeviceAuthKeyStoreInternal::new(mem);
        let mut authenticator = passkey::authenticator::Authenticator::new(
            crate::AAGUID,
            store,
            DeviceAuthKeyUiInternal {},
        )
        .hmac_secret(HmacSecretConfig::new_with_uv_only().enable_on_make_credential());
        let response = authenticator
            .make_credential(request)
            .await
            .expect("make_credential");
        let Ok(result) = MakeCredentialResult::try_from(response) else {
            panic!("make_credential response does not convert");
        };
        result
            .extensions
            .prf
            .and_then(|p| p.results)
            .expect("creation PRF")
            .first
    }

    #[tokio::test]
    async fn prf_output_at_creation_equals_prf_output_at_assertion() {
        let mut mem = MemStore::default();
        let created_prf = create_test_credential(&mut mem).await;

        // Assertion with the PRF input that the web vault sends.
        let client = Client::new(None);
        let mut dak = DeviceAuthKeyAuthenticator {
            client: &client,
            store: &mut mem,
        };
        let asserted = dak
            .assert_device_auth_key(GetAssertionRequest {
                rp_id: "localhost".to_string(),
                client_data_hash: vec![0u8; 32],
                allow_list: None,
                options: crate::types::Options {
                    rk: true,
                    uv: UV::Required,
                },
                extensions: Some(GetAssertionExtensionsInput {
                    prf: Some(GetAssertionPrfInput {
                        eval: Some(PrfInputValues {
                            first: sha256("passwordless-login".as_bytes()).to_vec(),
                            second: None,
                        }),
                        eval_by_credential: None,
                    }),
                }),
            })
            .await
            .expect("assert");
        let asserted_prf = asserted
            .extensions
            .prf
            .expect("assertion PRF")
            .results
            .first;

        assert_eq!(
            created_prf, asserted_prf,
            "creation and assertion PRF outputs differ"
        );

        // The PRF output for a local unlock is the same value.
        dak.store
            .create_metadata(DeviceAuthKeyMetadata {
                record_identifier: "record".to_string(),
                creation_date: Utc::now(),
                credential_id: vec![],
                rp_id: "localhost".to_string(),
                user_name: "dak@example.com".to_string(),
                user_display_name: "dak".to_string(),
                user_handle: vec![],
            })
            .await
            .expect("metadata");
        let unlock_prf = dak.get_prf_output().await.expect("unlock PRF");
        assert_eq!(unlock_prf, B64::from(created_prf.as_slice()));
    }

    #[tokio::test]
    async fn login_assertion_returns_token_device_response_and_prf_output() {
        let mut mem = MemStore::default();
        let created_prf = create_test_credential(&mut mem).await;

        let mut config = ApiConfigurations::from_api_client(
            bitwarden_api_api::apis::ApiClient::new_mocked(|_| {}),
        );
        config.identity_client = bitwarden_api_identity::apis::ApiClient::new_mocked(|mock| {
            mock.accounts_api
                .expect_get_web_authn_login_assertion_options()
                .returning(|| {
                    let mut options = bitwarden_api_identity::models::AssertionOptions::new();
                    options.challenge = Some((0u8..16).collect());
                    options.rp_id = Some("localhost".to_string());
                    Ok(
                        bitwarden_api_identity::models::WebAuthnLoginAssertionOptionsResponseModel {
                            object: None,
                            options: Box::new(options),
                            token: "token".to_string(),
                        },
                    )
                });
        });
        let client = Client::builder()
            .with_api_configurations(std::sync::Arc::new(config))
            .build();
        let mut dak = DeviceAuthKeyAuthenticator {
            client: &client,
            store: &mut mem,
        };

        let assertion = dak
            .assert_device_auth_key_for_login("https://localhost:8080".to_string())
            .await
            .expect("login assertion");

        assert_eq!(assertion.token, "token");
        assert_eq!(assertion.prf_output, B64::from(created_prf.as_slice()));
        let device_response: serde_json::Value =
            serde_json::from_str(&assertion.device_response).expect("device response JSON");
        assert_eq!(device_response["type"], "public-key");
        assert_eq!(device_response["id"], device_response["rawId"]);
        let client_data_json = B64Url::try_from(
            device_response["response"]["clientDataJSON"]
                .as_str()
                .expect("clientDataJSON"),
        )
        .expect("base64url");
        let client_data: serde_json::Value =
            serde_json::from_slice(client_data_json.as_bytes()).expect("client data");
        assert_eq!(client_data["type"], "webauthn.get");
        assert_eq!(client_data["challenge"], "AAECAwQFBgcICQoLDA0ODw");
        assert_eq!(client_data["origin"], "https://localhost:8080");
    }

    #[tokio::test]
    async fn assertion_returns_the_store_error_of_a_failed_record_read() {
        let mut mem = MemStore::default();
        create_test_credential(&mut mem).await;
        mem.cancel_record_read = true;
        mem.metadata = Some(DeviceAuthKeyMetadata {
            record_identifier: "record".to_string(),
            creation_date: Utc::now(),
            credential_id: vec![],
            rp_id: "localhost".to_string(),
            user_name: "dak@example.com".to_string(),
            user_display_name: "dak".to_string(),
            user_handle: vec![],
        });
        let client = Client::new(None);
        let mut dak = DeviceAuthKeyAuthenticator {
            client: &client,
            store: &mut mem,
        };

        let result = dak.get_prf_output().await;

        assert!(matches!(result, Err(DeviceAuthKeyError::UserCancelled)));
    }
}
