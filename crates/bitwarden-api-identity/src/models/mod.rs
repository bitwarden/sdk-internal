pub mod assertion_options;
pub use self::assertion_options::AssertionOptions;
pub mod authentication_extensions_client_inputs;
pub use self::authentication_extensions_client_inputs::AuthenticationExtensionsClientInputs;
pub mod authenticator_transport;
pub use self::authenticator_transport::AuthenticatorTransport;
pub mod kdf_type;
pub use self::kdf_type::KdfType;
pub mod keys_request_model;
pub use self::keys_request_model::KeysRequestModel;
pub mod prelogin_request_model;
pub use self::prelogin_request_model::PreloginRequestModel;
pub mod prelogin_response_model;
pub use self::prelogin_response_model::PreloginResponseModel;
pub mod product_tier_type;
pub use self::product_tier_type::ProductTierType;
pub mod product_type;
pub use self::product_type::ProductType;
pub mod public_key_credential_descriptor;
pub use self::public_key_credential_descriptor::PublicKeyCredentialDescriptor;
pub mod public_key_credential_type;
pub use self::public_key_credential_type::PublicKeyCredentialType;
pub mod register_finish_request_model;
pub use self::register_finish_request_model::RegisterFinishRequestModel;
pub mod register_request_model;
pub use self::register_request_model::RegisterRequestModel;
pub mod register_response_model;
pub use self::register_response_model::RegisterResponseModel;
pub mod register_send_verification_email_request_model;
pub use self::register_send_verification_email_request_model::RegisterSendVerificationEmailRequestModel;
pub mod register_verification_email_clicked_request_model;
pub use self::register_verification_email_clicked_request_model::RegisterVerificationEmailClickedRequestModel;
pub mod trial_send_verification_email_request_model;
pub use self::trial_send_verification_email_request_model::TrialSendVerificationEmailRequestModel;
pub mod user_verification_requirement;
pub use self::user_verification_requirement::UserVerificationRequirement;
pub mod web_authn_login_assertion_options_response_model;
pub use self::web_authn_login_assertion_options_response_model::WebAuthnLoginAssertionOptionsResponseModel;
/*
use serde::{Deserialize, Deserializer, Serializer};
use serde_with::{de::DeserializeAsWrap, ser::SerializeAsWrap, DeserializeAs, SerializeAs};
use std::marker::PhantomData;

pub(crate) struct DoubleOption<T>(PhantomData<T>);

impl<T, TAs> SerializeAs<Option<Option<T>>> for DoubleOption<TAs>
where
    TAs: SerializeAs<T>,
{
    fn serialize_as<S>(values: &Option<Option<T>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match values {
            None => serializer.serialize_unit(),
            Some(None) => serializer.serialize_none(),
            Some(Some(v)) => serializer.serialize_some(&SerializeAsWrap::<T, TAs>::new(v)),
        }
    }
}

impl<'de, T, TAs> DeserializeAs<'de, Option<Option<T>>> for DoubleOption<TAs>
where
    TAs: DeserializeAs<'de, T>,
    T: std::fmt::Debug,
{
    fn deserialize_as<D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Some(
            DeserializeAsWrap::<Option<T>, Option<TAs>>::deserialize(deserializer)?
                .into_inner(),
        ))
    }
}
*/
