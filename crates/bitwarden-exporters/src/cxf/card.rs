//! Credit card credential conversion
//!
//! Handles conversion between internal [Card] and credential exchange [CreditCardCredential].

use bitwarden_vault::CardBrand;
use credential_exchange_types::format::{Credential, CreditCardCredential};

use crate::Card;

impl From<Card> for Vec<Credential> {
    fn from(value: Card) -> Self {
        vec![Credential::CreditCard(Box::new(CreditCardCredential {
            number: value.number.unwrap_or_default(),
            full_name: value.cardholder_name.unwrap_or_default(),
            card_type: value.brand,
            verification_number: value.code,
            expiry_date: match (value.exp_year, value.exp_month) {
                (Some(year), Some(month)) => Some(format!("{}-{}", year, month)),
                _ => None,
            },
            valid_from: None,
        }))]
    }
}

impl From<&CreditCardCredential> for Card {
    fn from(value: &CreditCardCredential) -> Self {
        let (year, month) = value.expiry_date.as_ref().map_or((None, None), |date| {
            let parts: Vec<&str> = date.split('-').collect();
            let year = parts.first().map(|s| s.to_string());
            let month = parts.get(1).map(|s| s.to_string());
            (year, month)
        });

        Card {
            cardholder_name: Some(value.full_name.clone()),
            exp_month: month,
            exp_year: year,
            code: value.verification_number.clone(),
            brand: value
                .card_type
                .as_ref()
                .and_then(|brand| sanitize_brand(brand)),
            number: Some(value.number.clone()),
        }
    }
}

/// Sanitize credit card brand
///
/// Performs a fuzzy match on the string to find a matching brand. By converting to lowercase and
/// removing all whitespace.
///
/// - For recognized brands, the brand is normalized before being converted to a string.
/// - For unrecognized brands, `None` is returned.
fn sanitize_brand(value: &str) -> Option<String> {
    match value.to_lowercase().replace(" ", "").as_str() {
        "visa" => Some(CardBrand::Visa),
        "mastercard" => Some(CardBrand::Mastercard),
        "amex" | "americanexpress" => Some(CardBrand::Amex),
        "discover" => Some(CardBrand::Discover),
        "dinersclub" => Some(CardBrand::DinersClub),
        "jcb" => Some(CardBrand::Jcb),
        "maestro" => Some(CardBrand::Maestro),
        "unionpay" => Some(CardBrand::UnionPay),
        "rupay" => Some(CardBrand::RuPay),
        _ => None,
    }
    .and_then(|brand| serde_json::to_value(&brand).ok())
    .and_then(|v| v.as_str().map(|s| s.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_brand() {
        assert_eq!(sanitize_brand("Visa"), Some("Visa".to_string()));
        assert_eq!(sanitize_brand("  visa  "), Some("Visa".to_string()));
        assert_eq!(sanitize_brand("MasterCard"), Some("Mastercard".to_string()));
        assert_eq!(sanitize_brand("amex"), Some("Amex".to_string()));
        assert_eq!(sanitize_brand("American Express"), Some("Amex".to_string()));
        assert_eq!(
            sanitize_brand("DinersClub"),
            Some("Diners Club".to_string())
        );
        assert_eq!(sanitize_brand("j c b"), Some("JCB".to_string()));
        assert_eq!(sanitize_brand("Some unknown"), None);
    }

    #[test]
    fn test_card_to_credentials() {
        let card = Card {
            cardholder_name: Some("John Doe".to_string()),
            exp_month: Some("12".to_string()),
            exp_year: Some("2025".to_string()),
            code: Some("123".to_string()),
            brand: Some("Visa".to_string()),
            number: Some("4111111111111111".to_string()),
        };

        let credentials: Vec<Credential> = card.into();
        assert_eq!(credentials.len(), 1);

        if let Credential::CreditCard(credit_card) = &credentials[0] {
            assert_eq!(credit_card.full_name, "John Doe");
            assert_eq!(credit_card.expiry_date, Some("2025-12".to_string()));
            assert_eq!(credit_card.verification_number, Some("123".to_string()));
            assert_eq!(credit_card.card_type, Some("Visa".to_string()));
            assert_eq!(credit_card.number, "4111111111111111");
        } else {
            panic!("Expected CreditCardCredential");
        }
    }

    #[test]
    fn test_credit_card_credential_to_card() {
        let credit_card = CreditCardCredential {
            number: "4111111111111111".to_string(),
            full_name: "John Doe".to_string(),
            card_type: Some("Visa".to_string()),
            verification_number: Some("123".to_string()),
            expiry_date: Some("2025-12".to_string()),
            valid_from: None,
        };

        let card: Card = (&credit_card).into();
        assert_eq!(card.cardholder_name, Some("John Doe".to_string()));
        assert_eq!(card.exp_month, Some("12".to_string()));
        assert_eq!(card.exp_year, Some("2025".to_string()));
        assert_eq!(card.code, Some("123".to_string()));
        assert_eq!(card.brand, Some("Visa".to_string()));
        assert_eq!(card.number, Some("4111111111111111".to_string()));
    }
}
