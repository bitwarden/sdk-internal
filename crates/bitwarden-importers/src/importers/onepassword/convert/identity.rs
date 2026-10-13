//! The Identity category.

use bitwarden_exporters::Identity;

use super::{claimed::Claimed, value::render_value};
use crate::importers::onepassword::access::wire::VaultItemDetails;

/// The parts of 1Password's address object that have an identity slot.
const ADDRESS_PARTS: [&str; 5] = ["street", "city", "state", "zip", "country"];

/// Reads a personal identity. 1Password's template is far wider than Bitwarden's: the birth date,
/// job title, messenger handles and the other phone numbers have no slot and stay custom fields.
pub(super) fn identity(details: &VaultItemDetails) -> (Identity, Claimed) {
    let mut claimed = Claimed::default();
    // 1Password keeps the whole address in one field, so it is claimed only when every part it
    // fills in has a slot. Otherwise the leftover pass keeps all of it.
    let address = claimed.take(details, "address", |field| {
        let parts = field.value.as_ref()?.as_object()?;
        parts
            .iter()
            .all(|(part, value)| {
                ADDRESS_PARTS.contains(&part.as_str()) || render_value(None, value).is_none()
            })
            .then_some(parts)
    });
    let address_part = |part: &str| render_value(None, address?.get(part)?);

    let identity = Identity {
        title: None,
        first_name: claimed.take_text(details, "firstname"),
        middle_name: claimed.take_text(details, "initial"),
        last_name: claimed.take_text(details, "lastname"),
        address1: address_part("street"),
        address2: None,
        address3: None,
        city: address_part("city"),
        state: address_part("state"),
        postal_code: address_part("zip"),
        country: address_part("country"),
        company: claimed.take_text(details, "company"),
        email: claimed.take_text(details, "email"),
        phone: claimed.take_text(details, "defphone"),
        username: claimed.take_text(details, "username"),
        // 1Password keeps these in categories of their own, never on an identity.
        ssn: None,
        passport_number: None,
        license_number: None,
    };

    (identity, claimed)
}
