use bitwarden_crypto_sync_handler::CryptoSyncData;

use crate::error::Result;

/// Key management operations that run on every sync.
#[derive(uniffi::Object)]
pub struct CryptoSyncHandlerClient(
    pub(crate) bitwarden_crypto_sync_handler::CryptoSyncHandlerClient,
);

#[uniffi::export(async_runtime = "tokio")]
impl CryptoSyncHandlerClient {
    /// Runs the key management sync work. Call this after each sync, once the user's cryptographic
    /// state has been applied.
    ///
    /// The sync work itself never fails. The `Result` exists so that `data` failing to convert on
    /// the Rust side (e.g. a malformed `EncString` or key id from the server) reaches the caller as
    /// a thrown `BitwardenError` instead of an unexpected UniFFI error.
    pub async fn on_sync(&self, data: CryptoSyncData) -> Result<()> {
        self.0.on_sync(data).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::key_management::{
        MasterPasswordUnlockData, V2UpgradeToken, WebAuthnPrfUnlockOption,
        account_cryptographic_state::WrappedAccountCryptographicState,
    };
    use uniffi::{Lift, LiftArgsError, Lower, LowerReturn, RustBuffer, RustCallError};

    use super::*;
    use crate::{UniFfiTag, error::BitwardenError};

    const MALFORMED_KEY_ID: &str = "not-a-key-id";
    const VALID_KEY_ID: &str = "000102030405060708090a0b0c0d0e0f";

    /// Wire bytes of a `CryptoSyncData` whose only populated field is `user_key_id`. `KeyId` is
    /// lowered as a `String`, so an arbitrary string yields data that lifts up to the key id.
    fn data_with_user_key_id(user_key_id: &str) -> RustBuffer {
        const SOME: u8 = 1;
        let mut buf = Vec::new();

        // CryptoSyncData.user_decryption: Some(CryptoSyncUserDecryption { .. })
        buf.push(SOME);
        <Option<MasterPasswordUnlockData> as Lower<UniFfiTag>>::write(None, &mut buf);
        <Option<V2UpgradeToken> as Lower<UniFfiTag>>::write(None, &mut buf);
        <Option<Vec<WebAuthnPrfUnlockOption>> as Lower<UniFfiTag>>::write(None, &mut buf);
        <Option<String> as Lower<UniFfiTag>>::write(Some(user_key_id.to_owned()), &mut buf);

        // CryptoSyncData.account_cryptographic_state
        <Option<WrappedAccountCryptographicState> as Lower<UniFfiTag>>::write(None, &mut buf);

        RustBuffer::from_vec(buf)
    }

    #[test]
    fn test_valid_data_lifts() {
        let lifted =
            <CryptoSyncData as Lift<UniFfiTag>>::try_lift(data_with_user_key_id(VALID_KEY_ID))
                .expect("valid key id must lift");

        let user_key_id = lifted.user_decryption.and_then(|u| u.user_key_id);
        assert_eq!(
            user_key_id.map(|id| id.to_string()).as_deref(),
            Some(VALID_KEY_ID)
        );
    }

    #[test]
    fn test_malformed_data_fails_to_lift() {
        crate::setup_error_converter();

        let lifted =
            <CryptoSyncData as Lift<UniFfiTag>>::try_lift(data_with_user_key_id(MALFORMED_KEY_ID));

        let error = lifted.expect_err("malformed key id must not lift");
        assert!(matches!(
            error.downcast_ref::<BitwardenError>(),
            Some(BitwardenError::Conversion(_))
        ));
    }

    #[test]
    fn test_failed_lift_is_returned_as_bitwarden_error() {
        crate::setup_error_converter();
        let error =
            <CryptoSyncData as Lift<UniFfiTag>>::try_lift(data_with_user_key_id(MALFORMED_KEY_ID))
                .expect_err("malformed key id must not lift");

        // Mirrors what the generated `on_sync` scaffolding does when lifting `data` fails. An
        // `Error` result is thrown as `BitwardenError`; an `InternalError` would surface as
        // `UniffiInternalError` on Swift and `InternalException` on Kotlin.
        let returned = <Result<()> as LowerReturn<UniFfiTag>>::handle_failed_lift(LiftArgsError {
            arg_name: "data",
            error,
        });

        assert!(matches!(returned, Err(RustCallError::Error(_))));
    }
}
