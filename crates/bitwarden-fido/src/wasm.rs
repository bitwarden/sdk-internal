use bitwarden_iter::BwIterator;
use bitwarden_vault::CipherListViewIterator;
use itertools::Itertools;
use wasm_bindgen::prelude::*;

use crate::{CredentialsForAutofillError, Fido2CredentialAutofillView};

#[wasm_bindgen]
#[allow(missing_docs)]
pub struct Fido2CredentialAutofillViewIterator(
    BwIterator<Result<Fido2CredentialAutofillView, CredentialsForAutofillError>>,
);

#[wasm_bindgen]
impl Fido2CredentialAutofillViewIterator {
    #[allow(missing_docs)]
    pub fn next(&mut self) -> Option<Fido2CredentialAutofillView> {
        // Simplify the return because wasm_bindgen doesn't like Option<Result<T, E>> and I'm just
        // proving the concept
        self.0.iter.next().transpose().ok().flatten()
    }
}

#[wasm_bindgen]
#[allow(missing_docs)]
pub async fn credentials_for_autofill_stream(
    all_credentials: CipherListViewIterator,
) -> Result<Fido2CredentialAutofillViewIterator, CredentialsForAutofillError> {
    let iter = all_credentials
        .into_iter()
        .map(
            |cipher| -> Result<Vec<Fido2CredentialAutofillView>, CredentialsForAutofillError> {
                Ok(Fido2CredentialAutofillView::from_cipher_list_view(
                    &cipher?,
                )?)
            },
        )
        .flatten_ok();

    Ok(Fido2CredentialAutofillViewIterator(BwIterator::new(iter)))
}
