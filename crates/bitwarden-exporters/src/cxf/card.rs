//! Credit card credential conversion
//!
//! Handles conversion between internal [Card] and credential exchange [CreditCardCredential].

use bitwarden_vault::CardBrand;
use chrono::Month;
use credential_exchange_format::{Credential, CreditCardCredential, EditableFieldYearMonth};
use num_traits::FromPrimitive;

use crate::{Card, Field, cxf::editable_field::create_field};

impl From<Card> for Vec<Credential> {
    fn from(value: Card) -> Self {
        let expiry_date = match (value.exp_year, value.exp_month) {
            (Some(year), Some(month)) => {
                let year_parsed = year.parse().ok();
                let numeric_month: Option<u32> = month.parse().ok();
                let month_parsed = numeric_month.and_then(Month::from_u32);
                match (year_parsed, month_parsed) {
                    (Some(year), Some(month)) => {
                        Some(EditableFieldYearMonth { year, month }.into())
                    }
                    _ => None,
                }
            }
            _ => None,
        };

        vec![Credential::CreditCard(Box::new(CreditCardCredential {
            number: value.number.map(|v| v.into()),
            full_name: value.cardholder_name.map(|v| v.into()),
            card_type: value.brand.map(|v| v.into()),
            verification_number: value.code.map(|v| v.into()),
            pin: None,
            expiry_date,
            valid_from: None,
        }))]
    }
}

impl From<&CreditCardCredential> for Card {
    fn from(value: &CreditCardCredential) -> Self {
        Card {
            cardholder_name: value.full_name.clone().map(|v| v.into()),
            exp_month: value
                .expiry_date
                .as_ref()
                .map(|v| v.value.month.number_from_month().to_string()),
            exp_year: value.expiry_date.as_ref().map(|v| v.value.year.to_string()),
            code: value.verification_number.clone().map(|v| v.into()),
            brand: value
                .card_type
                .as_ref()
                .and_then(|brand| sanitize_brand(&brand.value.0)),
            number: value.number.clone().map(|v| v.into()),
        }
    }
}

pub(super) fn to_card(credential: &CreditCardCredential) -> (Card, Vec<Field>) {
    let card = credential.into();

    let fields = [
        credential
            .pin
            .as_ref()
            .map(|v| create_field(v, Some("PIN"))),
        credential
            .valid_from
            .as_ref()
            .map(|v| create_field(v, Some("Valid From"))),
    ]
    .into_iter()
    .flatten()
    .collect();

    (card, fields)
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
    use bitwarden_vault::FieldType;
    use chrono::Month;
    use credential_exchange_format::EditableFieldYearMonth;

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
            assert_eq!(credit_card.full_name.as_ref().unwrap().value.0, "John Doe");
            assert_eq!(
                credit_card.expiry_date.as_ref().unwrap().value,
                EditableFieldYearMonth {
                    year: 2025,
                    month: Month::December
                }
            );
            assert_eq!(
                credit_card.verification_number.as_ref().unwrap().value.0,
                "123".to_string()
            );
            assert_eq!(
                credit_card.card_type.as_ref().unwrap().value.0,
                "Visa".to_string()
            );
            assert_eq!(
                credit_card.number.as_ref().unwrap().value.0,
                "4111111111111111"
            );
        } else {
            panic!("Expected CreditCardCredential");
        }
    }

    #[test]
    fn test_credit_card_credential_to_card() {
        let credit_card = CreditCardCredential {
            number: Some("4111111111111111".to_string().into()),
            full_name: Some("John Doe".to_string().into()),
            card_type: Some("Visa".to_string().into()),
            verification_number: Some("123".to_string().into()),
            pin: Some("4567".to_string().into()),
            expiry_date: Some(
                EditableFieldYearMonth {
                    year: 2025,
                    month: Month::December,
                }
                .into(),
            ),
            valid_from: Some(
                EditableFieldYearMonth {
                    year: 2024,
                    month: Month::January,
                }
                .into(),
            ),
        };

        let (card, fields) = to_card(&credit_card);
        assert_eq!(card.cardholder_name, Some("John Doe".to_string()));
        assert_eq!(card.exp_month, Some("12".to_string()));
        assert_eq!(card.exp_year, Some("2025".to_string()));
        assert_eq!(card.code, Some("123".to_string()));
        assert_eq!(card.brand, Some("Visa".to_string()));
        assert_eq!(card.number, Some("4111111111111111".to_string()));

        assert_eq!(
            fields,
            vec![
                Field {
                    name: Some("PIN".to_string()),
                    value: Some("4567".to_string()),
                    r#type: FieldType::Hidden as u8,
                    linked_id: None,
                },
                Field {
                    name: Some("Valid From".to_string()),
                    value: Some("2024-01".to_string()),
                    r#type: FieldType::Text as u8,
                    linked_id: None,
                },
            ]
        )
    }
}
