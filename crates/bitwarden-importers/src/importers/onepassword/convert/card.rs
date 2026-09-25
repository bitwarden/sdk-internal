//! The Credit Card category.

use bitwarden_exporters::Card;

use super::{claimed::Claimed, value::month_year};
use crate::importers::onepassword::access::wire::{VaultItemDetails, VaultItemSectionField};

/// Reads a payment card. Every slot is optional, so an item that fills none of them still becomes
/// a card rather than losing its category.
pub(super) fn card(details: &VaultItemDetails) -> (Card, Claimed) {
    let mut claimed = Claimed::default();
    let (exp_month, exp_year) = claimed.take(details, "expiry", expiry).unzip();

    let card = Card {
        cardholder_name: claimed.take_text(details, "cardholder"),
        exp_month,
        exp_year,
        code: claimed.take_text(details, "cvv"),
        // An unrecognized card type stays a custom field rather than reaching the vault as a brand
        // Bitwarden does not know.
        brand: claimed.take(details, "type", |field| {
            card_brand(field.value.as_ref()?.as_str()?)
        }),
        number: claimed.take_text(details, "ccnum"),
    };

    (card, claimed)
}

/// Splits 1Password's `202811` into the month and year Bitwarden keeps apart. The month drops its
/// leading zero, the form the rest of the vault uses.
fn expiry(field: &VaultItemSectionField) -> Option<(String, String)> {
    let (year, month) = month_year(field.value.as_ref()?.as_i64()?)?;
    Some((month.to_string(), year.to_string()))
}

/// Maps a 1Password card type onto a Bitwarden brand. 1Password writes its own ids, so `mc` and
/// `diners` have to be spelled out rather than passed through.
pub(super) fn card_brand(kind: &str) -> Option<String> {
    let brand = match kind.to_lowercase().replace(' ', "").as_str() {
        "visa" => "Visa",
        "mc" | "mastercard" => "Mastercard",
        "amex" | "americanexpress" => "Amex",
        "discover" => "Discover",
        "diners" | "dinersclub" => "Diners Club",
        "jcb" => "JCB",
        "maestro" => "Maestro",
        "unionpay" => "UnionPay",
        "rupay" => "RuPay",
        _ => return None,
    };

    Some(brand.to_string())
}
