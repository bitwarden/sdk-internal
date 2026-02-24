use bitwarden_api_api::models::{
    AuthenticatorAttestationRawResponse, CredentialCreateOptions, PublicKeyCredentialType,
    ResponseData, SecretVerificationRequestModel, UserVerificationRequirement,
    WebAuthnCredentialCreateOptionsResponseModel, WebAuthnLoginCredentialCreateRequestModel,
};
use bitwarden_core::{
    Client, key_management::SymmetricKeyId, mobile::KdfClient, platform::SecretVerificationRequest,
};
use bitwarden_crypto::{HashPurpose, Kdf, RotateableKeySet};
use chrono::{DateTime, Utc};
use coset::{CborSerializable, CoseKey};
use passkey::{
    authenticator::{
        DiscoverabilitySupport, StoreInfo, UiHint, UserCheck, extensions::HmacSecretConfig,
    },
    types::{
        CredentialExtensions, Passkey, StoredHmacSecret,
        crypto::sha256,
        ctap2::{
            self, Ctap2Error, StatusCode, UnknownSpecError, VendorError,
            extensions::{AuthenticatorPrfInputs, AuthenticatorPrfValues},
            make_credential::Options,
        },
    },
};
use uuid::Uuid;

use crate::{
    GetAssertionRequest, MakeCredentialResult, PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    types::{
        GetAssertionExtensionsOutput, PublicKeyCredentialDescriptor, PublicKeyCredentialParameters,
        UV, WebAuthnEntityError,
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
    /// The passkey private key and metadata will be stored on the device using the provided trait implementation.
    pub async fn create_device_auth_key(
        &mut self,
        client_name: String,
        web_vault_hostname: String,
        origin: String,
        // TODO: These parameters are limiting:
        // - Is there some way to accept the master password hash directly instead of having to do it in here?
        // - Do we need to support all the options (master password hash, OTP, secret, auth access token)? Or just master password hash and OTP?
        // We do this in get_user_api_key, consider centralizing this logic
        email: String,
        secret_verification_request: SecretVerificationRequest,
        kdf_params: Kdf,
    ) -> Result<(), DeviceAuthKeyError> {
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
        let (request, client_data_json) = convert_creation_options(options.as_ref(), web_vault_hostname, origin).map_err(|err| {
            tracing::error!(%err, ?options, "Received invalid WebAuthn, attestation options from server");
            DeviceAuthKeyError::RetrieveRegistrationOptionsFailure
        })?;

        // Create credential with passkey-rs, store on device with given trait implementation
        let store = DeviceAuthKeyStoreInternal { store: self.store };
        let ui = DeviceAuthKeyUiInternal {};
        let mut authenticator =
            passkey::authenticator::Authenticator::new(super::AAGUID, store, ui)
                .hmac_secret(HmacSecretConfig::new_with_uv_only().enable_on_make_credential());
        let response = authenticator
            .make_credential(request)
            .await
            .map_err(|status_code| {
                tracing::error!(?status_code, "Failed to make FIDO credential");
                DeviceAuthKeyError::AuthenticatorFailure
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
            RotateableKeySet::new(&ctx, &prf_key, SymmetricKeyId::User).map_err(|err| {
                tracing::error!(%err, "Failed to generate rotateable key set from PRF output");
                DeviceAuthKeyError::PrfFailure
            })?
        };

        // Send registration request to server
        let create_request = WebAuthnLoginCredentialCreateRequestModel {
            device_response: Box::new(AuthenticatorAttestationRawResponse {
                id: Some(result.credential_id.clone()),
                raw_id: Some(result.credential_id),
                r#type: Some(PublicKeyCredentialType::PublicKey),
                response: Some(Box::new(ResponseData {
                    attestation_object: Some(result.attestation_object),
                    client_data_json: Some(client_data_json.into_bytes()),
                })),
                extensions: None,
            }),
            name: client_name,
            token,
            supports_prf: true,
            encrypted_user_key: Some(key_set.encapsulated_downstream_key.to_string()),
            encrypted_public_key: Some(key_set.encrypted_encapsulation_key.to_string()),
            encrypted_private_key: Some(key_set.encrypted_decapsulation_key.to_string()),
        };
        api_client
            .web_authn_api()
            .post(Some(create_request))
            .await
            .map_err(|_| DeviceAuthKeyError::SubmitRegistrationFailure)?;
        Ok(())
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
        let store = DeviceAuthKeyStoreInternal { store: self.store };
        let ui = DeviceAuthKeyUiInternal {};
        let mut authenticator =
            passkey::authenticator::Authenticator::new(super::AAGUID, store, ui)
                .hmac_secret(HmacSecretConfig::new_with_uv_only().enable_on_make_credential());
        let response = authenticator
            .get_assertion(request)
            .await
            .map_err(|status_code| {
                tracing::error!(?status_code, "Authenticator failed to assert credential");
                DeviceAuthKeyError::AuthenticatorFailure
            })?;

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
        _credential_id: Vec<u8>,
        _secret_request_verification: SecretVerificationRequest,
    ) -> Result<(), DeviceAuthKeyError> {
        self.store.delete_record_and_metadata().await?;
        // TODO: This cannot be implemented because there's no way to get the
        // database record ID from a credential ID. This needs server work.

        /*
        let record_id = loop {
            let responses = self
                .api
                .web_authn_api()
                .get()
                .await
                .map_err(|_| DeviceAuthKeyError::Unknown)?;
            let Some(data) = responses.data else {
                break None;
            };
            let id = data.iter().find_map(|m| match m.credential_id {
                Some(cred_id) if cred_id == credential_id => Some(m.id),
                None => None,
            });
            if id.is_some() {
                break id;
            }
        };
        if let Some(id) = {
            self.api
                .web_authn_api()
                .delete(id, Some(secret_request_verification_model))
                .await
                .map_err(|_| DeviceAuthKeyError::Unknown)?;
        }
        */
        Err(DeviceAuthKeyError::NotImplemented)
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

    // TODO: Make this an enum?
    Ok(SecretVerificationRequestModel {
        master_password_hash,
        otp: input.otp.clone(),
        auth_request_access_code: None,
        secret: None,
    })
}

/// Create a CTAP2 makeCredential request and clientDataJSON from the WebAuthn credential attestations options received from the server.
/// Generates clientDataJSON from given origin and challenge, and injects the default RP ID if it's missing.
fn convert_creation_options(
    options: &CredentialCreateOptions,
    default_rp_id: String,
    origin: String,
) -> Result<(passkey::types::ctap2::make_credential::Request, String), WebAuthnEntityError> {
    let mut missing_fields = Vec::with_capacity(0);
    if options.rp.is_none() {
        missing_fields.push("rp".to_string());
    }
    if options.user.is_none() {
        missing_fields.push("user".to_string());
    }
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
        rp: Some(rp),
        user: Some(user),
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

    let challenge_b64 = bitwarden_encoding::B64Url::from(challenge.as_ref())
        .to_string()
        .trim_end_matches('=')
        .to_string();
    let client_data_json = format!(
        r#"{{"type":"webauthn.create","challenge":"{}","origin":"{}","crossOrigin":false}}"#,
        challenge_b64, origin
    );
    let client_data_hash = passkey::types::crypto::sha256(client_data_json.as_bytes()).to_vec();

    // Inject default RP ID
    let mut rp = rp.clone();
    rp.id.get_or_insert(default_rp_id);
    let rp = TryInto::<PublicKeyCredentialRpEntity>::try_into(rp.as_ref())?.into();

    let user_entity = TryInto::<PublicKeyCredentialUserEntity>::try_into(user.as_ref())?.into();
    let pub_key_cred_params = pub_key_cred_params
        .into_iter()
        .map(|p| {
            PublicKeyCredentialParameters::try_from(p).and_then(|ours| {
                passkey::types::webauthn::PublicKeyCredentialParameters::try_from(ours)
            })
        })
        .collect::<Result<Vec<passkey::types::webauthn::PublicKeyCredentialParameters>, _>>()?;
    let exclude_list = exclude_credentials
        .as_ref()
        .map(|l| {
            l.into_iter()
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
            rk: o.require_resident_key.unwrap_or_default(),
            uv: if let Some(UserVerificationRequirement::Discouraged) = o.user_verification {
                false
            } else {
                true
            },
            up: true,
        })
        .unwrap_or_else(|| Options {
            rk: false,
            uv: true,
            up: true,
        });

    // Note, we currently hard-code this value instead of getting it from the server.
    let prf_input = AuthenticatorPrfInputs {
        eval: Some(AuthenticatorPrfValues {
            first: sha256("passwordless-login".as_bytes()),
            second: None,
        }),
        eval_by_credential: None,
    };

    let request = passkey::types::ctap2::make_credential::Request {
        client_data_hash: client_data_hash.into(),
        rp,
        user: user_entity,
        pub_key_cred_params,
        exclude_list,
        options: authenticator_options,
        extensions: extensions
            .as_ref()
            .map(|_| ctap2::make_credential::ExtensionInputs {
                hmac_secret: None,
                hmac_secret_mc: None,
                prf: Some(prf_input),
            }),
        pin_auth: None,
        pin_protocol: None,
    };
    Ok((request, client_data_json))
}

/// Fields corresponding to a WebAuthn [PublicKeyCredential][pub-key-cred]
/// with an [AuthenticatorAssertionResponse][authenticator-assertion-response].
///
/// Similar to [GetAssertionResult][crate::GetAssertionResult], but without the reference to the vault cipher.
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

    /// Private key material.
    pub key: Vec<u8>,

    /// COSE algorithm identifier for the key.
    pub key_alg: i64,

    /// COSE elliptic curve identifier for the key.
    pub key_curve: i64,

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
            key_alg: -7,  // ECDSA w/ SHA-256
            key_curve: 1, // P-256
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

/// Errors related to processing the device auth key.
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
#[derive(Debug, thiserror::Error)]
pub enum DeviceAuthKeyError {
    /// Authenticator failed to produce a valid response.
    #[error("The authenticator failed to produce a valid response")]
    AuthenticatorFailure,

    /// Failed to convert between Rust types.
    #[error("Failed to convert between Rust types")]
    ConversionError,

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

    /// Failed to generate rotateable key set from PRF output.
    #[error("Failed to generate rotateable key set from PRF output")]
    PrfFailure,

    /// Failed to submit registration request to the server.
    #[error("Failed to submit registration request to the server")]
    SubmitRegistrationFailure,
}

/// A trait used to interact with the device auth key data on the device.
#[async_trait::async_trait]
pub trait DeviceAuthKeyStore: Send + Sync {
    /// Create a record and its metadata.
    ///
    /// The record should be stored in device-bound storage and protected with user-verifying access
    /// controls. The metadata should be stored separately without access controls that require
    /// UI.
    async fn create_record_and_metadata(
        &mut self,
        record: DeviceAuthKeyRecord,
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
            Err(_) => Err(VendorError::try_from(0xf0).unwrap().into()),
        }
    }

    async fn save_credential(
        &mut self,
        cred: Passkey,
        user: passkey::types::ctap2::make_credential::PublicKeyCredentialUserEntity,
        rp: passkey::types::ctap2::make_credential::PublicKeyCredentialRpEntity,
        _options: passkey::types::ctap2::get_assertion::Options,
    ) -> Result<(), StatusCode> {
        // TODO: we need to modify the server to return the ID returned from the
        // server when registering the credential, then save it as the record
        // identifier so we can unregister it later.
        //
        // If we add a delete-by-cred-id method to the server instead, we can reuse the credential
        // ID here.
        let record_identifier = Uuid::new_v4().to_string();
        // We require the user name in our implementation. We should document this on the server.
        let (Some(user_name), Some(user_display_name)) = (user.name, user.display_name) else {
            return Err(UnknownSpecError::try_from(0xdf).unwrap().into());
        };
        let metadata = DeviceAuthKeyMetadata {
            record_identifier,
            creation_date: chrono::offset::Utc::now(),
            credential_id: cred.credential_id.to_vec(),
            rp_id: rp.id,
            user_handle: user.id.to_vec(),
            user_name,
            user_display_name,
        };
        let record = cred
            .try_into()
            .map_err(|_| UnknownSpecError::try_from(0xdf).unwrap())?;

        self.store
            .create_record_and_metadata(record, metadata)
            .await
            .map_err(|_| StatusCode::from(UnknownSpecError::try_from(0xdf).unwrap()))?;
        Ok(())
    }

    async fn update_credential(&mut self, _cred: Passkey) -> Result<(), StatusCode> {
        // This is only used to update the conuter, which we're not currently using.
        unimplemented!()
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
