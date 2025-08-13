//! Credit card cipher implementation with formatting utilities.
//! 
//! This module provides data structures and formatting functions for credit card information
//! stored in Bitwarden vaults. It includes both encrypted storage (`Card`) and decrypted view
//! (`CardView`) representations.
//!
//! ## Formatting Features
//! 
//! The module provides two main formatting functions for credit card numbers:
//! 
//! - `format_number()`: Standard 4-4-4-4 digit formatting
//! - `format_number_by_brand()`: Brand-specific formatting for better UX
//!
//! ### Supported Brand Formats
//!
//! - **American Express**: XXXX XXXXXX XXXXX (4-6-5)
//! - **Diners Club**: XXXX XXXXXX XXXX (4-6-4) for 14-digit cards
//! - **All others**: XXXX XXXX XXXX XXXX (4-4-4-4)

use bitwarden_api_api::models::CipherCardModel;
use bitwarden_core::key_management::{KeyIds, SymmetricKeyId};
use bitwarden_crypto::{
    CompositeEncryptable, CryptoError, Decryptable, EncString, KeyStoreContext,
    PrimitiveEncryptable,
};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

use super::cipher::CipherKind;
use crate::{cipher::cipher::CopyableCipherFields, Cipher, VaultParseError};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct Card {
    pub cardholder_name: Option<EncString>,
    pub exp_month: Option<EncString>,
    pub exp_year: Option<EncString>,
    pub code: Option<EncString>,
    pub brand: Option<EncString>,
    pub number: Option<EncString>,
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct CardView {
    pub cardholder_name: Option<String>,
    pub exp_month: Option<String>,
    pub exp_year: Option<String>,
    pub code: Option<String>,
    pub brand: Option<String>,
    pub number: Option<String>,
}

/// Minimal CardView only including the needed details for list views
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct CardListView {
    /// The brand of the card, e.g. Visa, Mastercard, etc.
    pub brand: Option<String>,
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize)]
pub enum CardBrand {
    Visa,
    Mastercard,
    Amex,
    Discover,
    #[serde(rename = "Diners Club")]
    DinersClub,
    #[serde(rename = "JCB")]
    Jcb,
    Maestro,
    UnionPay,
    RuPay,
    #[serde(untagged)]
    Other,
}

impl CompositeEncryptable<KeyIds, SymmetricKeyId, Card> for CardView {
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<Card, CryptoError> {
        Ok(Card {
            cardholder_name: self.cardholder_name.encrypt(ctx, key)?,
            exp_month: self.exp_month.encrypt(ctx, key)?,
            exp_year: self.exp_year.encrypt(ctx, key)?,
            code: self.code.encrypt(ctx, key)?,
            brand: self.brand.encrypt(ctx, key)?,
            number: self.number.encrypt(ctx, key)?,
        })
    }
}

impl Decryptable<KeyIds, SymmetricKeyId, CardListView> for Card {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<CardListView, CryptoError> {
        Ok(CardListView {
            brand: self.brand.decrypt(ctx, key).ok().flatten(),
        })
    }
}

impl Decryptable<KeyIds, SymmetricKeyId, CardView> for Card {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<CardView, CryptoError> {
        Ok(CardView {
            cardholder_name: self.cardholder_name.decrypt(ctx, key).ok().flatten(),
            exp_month: self.exp_month.decrypt(ctx, key).ok().flatten(),
            exp_year: self.exp_year.decrypt(ctx, key).ok().flatten(),
            code: self.code.decrypt(ctx, key).ok().flatten(),
            brand: self.brand.decrypt(ctx, key).ok().flatten(),
            number: self.number.decrypt(ctx, key).ok().flatten(),
        })
    }
}

impl TryFrom<CipherCardModel> for Card {
    type Error = VaultParseError;

    fn try_from(card: CipherCardModel) -> Result<Self, Self::Error> {
        Ok(Self {
            cardholder_name: EncString::try_from_optional(card.cardholder_name)?,
            exp_month: EncString::try_from_optional(card.exp_month)?,
            exp_year: EncString::try_from_optional(card.exp_year)?,
            code: EncString::try_from_optional(card.code)?,
            brand: EncString::try_from_optional(card.brand)?,
            number: EncString::try_from_optional(card.number)?,
        })
    }
}

impl CardView {
    /// Formats a credit card number in groups of 4 digits separated by spaces for display.
    /// This should only be called when the card number should be unmasked for the user.
    ///
    /// Returns `None` if the card number is `None` or empty.
    /// Strips all non-digit characters before formatting.
    ///
    /// # Examples
    /// ```
    /// use bitwarden_vault::CardView;
    /// 
    /// let card = CardView {
    ///     number: Some("4111111111111111".to_string()),
    ///     // ... other fields
    ///     # cardholder_name: None,
    ///     # exp_month: None,
    ///     # exp_year: None,
    ///     # code: None,
    ///     # brand: None,
    /// };
    /// 
    /// assert_eq!(card.format_number(), Some("4111 1111 1111 1111".to_string()));
    /// ```
    pub fn format_number(&self) -> Option<String> {
        let number = self.number.as_ref()?;
        
        if number.is_empty() {
            return None;
        }
        
        // Extract only digits from the input
        let digits: String = number.chars().filter(|c| c.is_ascii_digit()).collect();
        
        if digits.is_empty() {
            return None;
        }
        
        // Group digits into chunks of 4, separated by spaces
        let formatted: String = digits
            .chars()
            .enumerate()
            .flat_map(|(i, c)| {
                if i > 0 && i % 4 == 0 {
                    vec![' ', c]
                } else {
                    vec![c]
                }
            })
            .collect();
        
        Some(formatted)
    }

    /// Formats a credit card number with brand-specific formatting for display.
    /// This provides better UX by using the formatting conventions specific to each card brand.
    /// Falls back to standard 4-4-4-4 formatting for unknown brands.
    ///
    /// Returns `None` if the card number is `None` or empty.
    /// Strips all non-digit characters before formatting.
    ///
    /// # Brand-specific formats:
    /// - **American Express**: XXXX XXXXXX XXXXX (4-6-5)
    /// - **Diners Club**: XXXX XXXXXX XXXX (4-6-4) for 14-digit cards
    /// - **All others**: XXXX XXXX XXXX XXXX (4-4-4-4)
    ///
    /// # Examples
    /// ```
    /// use bitwarden_vault::CardView;
    /// 
    /// // Amex card
    /// let amex_card = CardView {
    ///     number: Some("378282246310005".to_string()),
    ///     brand: Some("Amex".to_string()),
    ///     // ... other fields
    ///     # cardholder_name: None,
    ///     # exp_month: None,
    ///     # exp_year: None,
    ///     # code: None,
    /// };
    /// 
    /// assert_eq!(amex_card.format_number_by_brand(), Some("3782 822463 10005".to_string()));
    /// 
    /// // Visa card
    /// let visa_card = CardView {
    ///     number: Some("4111111111111111".to_string()),
    ///     brand: Some("Visa".to_string()),
    ///     // ... other fields
    ///     # cardholder_name: None,
    ///     # exp_month: None,
    ///     # exp_year: None,
    ///     # code: None,
    /// };
    /// 
    /// assert_eq!(visa_card.format_number_by_brand(), Some("4111 1111 1111 1111".to_string()));
    /// ```
    pub fn format_number_by_brand(&self) -> Option<String> {
        let number = self.number.as_ref()?;
        
        if number.is_empty() {
            return None;
        }
        
        // Extract only digits from the input
        let digits: String = number.chars().filter(|c| c.is_ascii_digit()).collect();
        
        if digits.is_empty() {
            return None;
        }

        // Determine brand-specific formatting
        let brand = self.brand.as_deref().unwrap_or("").to_lowercase();
        
        match brand.as_str() {
            "amex" | "american express" => self.format_amex_style(&digits),
            "diners club" | "dinersclub" | "diners" => self.format_diners_style(&digits),
            _ => self.format_standard_style(&digits),
        }
    }

    /// Format American Express cards as XXXX XXXXXX XXXXX (4-6-5)
    fn format_amex_style(&self, digits: &str) -> Option<String> {
        if digits.len() != 15 {
            // Amex should be 15 digits, fall back to standard if not
            return self.format_standard_style(digits);
        }
        
        Some(format!("{} {} {}",
            &digits[0..4],
            &digits[4..10],
            &digits[10..15]
        ))
    }

    /// Format Diners Club cards as XXXX XXXXXX XXXX (4-6-4) for 14-digit cards
    fn format_diners_style(&self, digits: &str) -> Option<String> {
        if digits.len() == 14 {
            Some(format!("{} {} {}",
                &digits[0..4],
                &digits[4..10],
                &digits[10..14]
            ))
        } else {
            // Fall back to standard formatting for non-14-digit Diners cards
            self.format_standard_style(digits)
        }
    }

    /// Format standard cards as XXXX XXXX XXXX XXXX (4-4-4-4)
    fn format_standard_style(&self, digits: &str) -> Option<String> {
        let formatted: String = digits
            .chars()
            .enumerate()
            .flat_map(|(i, c)| {
                if i > 0 && i % 4 == 0 {
                    vec![' ', c]
                } else {
                    vec![c]
                }
            })
            .collect();
        
        Some(formatted)
    }
}

impl CipherKind for Card {
    fn decrypt_subtitle(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<String, CryptoError> {
        let brand = self
            .brand
            .as_ref()
            .map(|b| b.decrypt(ctx, key))
            .transpose()?;
        let number = self
            .number
            .as_ref()
            .map(|n| n.decrypt(ctx, key))
            .transpose()?;

        Ok(build_subtitle_card(brand, number))
    }

    fn get_copyable_fields(&self, _: Option<&Cipher>) -> Vec<CopyableCipherFields> {
        [
            self.number
                .as_ref()
                .map(|_| CopyableCipherFields::CardNumber),
            self.code
                .as_ref()
                .map(|_| CopyableCipherFields::CardSecurityCode),
        ]
        .into_iter()
        .flatten()
        .collect()
    }
}

/// Builds the subtitle for a card cipher
fn build_subtitle_card(brand: Option<String>, number: Option<String>) -> String {
    // Attempt to pre-allocate the string with the expected max-size
    let mut subtitle =
        String::with_capacity(brand.as_ref().map(|b| b.len()).unwrap_or_default() + 8);

    if let Some(brand) = brand {
        subtitle.push_str(&brand);
    }

    if let Some(number) = number {
        let number_chars: Vec<_> = number.chars().collect();
        let number_len = number_chars.len();
        if number_len > 4 {
            if !subtitle.is_empty() {
                subtitle.push_str(", ");
            }

            // On AMEX cards we show 5 digits instead of 4
            let digit_count = match number_chars[0..2] {
                ['3', '4'] | ['3', '7'] => 5,
                _ => 4,
            };

            subtitle.push('*');
            subtitle.extend(number_chars.iter().skip(number_len - digit_count));
        }
    }

    subtitle
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_subtitle_card_visa() {
        let brand = Some("Visa".to_owned());
        let number = Some("4111111111111111".to_owned());

        let subtitle = build_subtitle_card(brand, number);
        assert_eq!(subtitle, "Visa, *1111");
    }

    #[test]
    fn test_build_subtitle_card_mastercard() {
        let brand = Some("Mastercard".to_owned());
        let number = Some("5555555555554444".to_owned());

        let subtitle = build_subtitle_card(brand, number);
        assert_eq!(subtitle, "Mastercard, *4444");
    }

    #[test]
    fn test_build_subtitle_card_amex() {
        let brand = Some("Amex".to_owned());
        let number = Some("378282246310005".to_owned());

        let subtitle = build_subtitle_card(brand, number);
        assert_eq!(subtitle, "Amex, *10005");
    }

    #[test]
    fn test_build_subtitle_card_underflow() {
        let brand = Some("Mastercard".to_owned());
        let number = Some("4".to_owned());

        let subtitle = build_subtitle_card(brand, number);
        assert_eq!(subtitle, "Mastercard");
    }

    #[test]
    fn test_build_subtitle_card_only_brand() {
        let brand = Some("Mastercard".to_owned());
        let number = None;

        let subtitle = build_subtitle_card(brand, number);
        assert_eq!(subtitle, "Mastercard");
    }

    #[test]
    fn test_build_subtitle_card_only_card() {
        let brand = None;
        let number = Some("5555555555554444".to_owned());

        let subtitle = build_subtitle_card(brand, number);
        assert_eq!(subtitle, "*4444");
    }
    #[test]
    fn test_get_copyable_fields_code() {
        let card = Card {
            cardholder_name: None,
            exp_month: None,
            exp_year: None,
            code: Some("2.6TpmzzaQHgYr+mXjdGLQlg==|vT8VhfvMlWSCN9hxGYftZ5rjKRsZ9ofjdlUCx5Gubnk=|uoD3/GEQBWKKx2O+/YhZUCzVkfhm8rFK3sUEVV84mv8=".parse().unwrap()),
            brand: None,
            number: None,
        };

        let copyable_fields = card.get_copyable_fields(None);

        assert_eq!(
            copyable_fields,
            vec![CopyableCipherFields::CardSecurityCode]
        );
    }

    #[test]
    fn test_build_subtitle_card_unicode() {
        let brand = Some("Visa".to_owned());
        let number = Some("•••• 3278".to_owned());

        let subtitle = build_subtitle_card(brand, number);
        assert_eq!(subtitle, "Visa, *3278");
    }

    #[test]
    fn test_get_copyable_fields_number() {
        let card = Card {
            cardholder_name: None,
            exp_month: None,
            exp_year: None,
            code: None,
            brand: None,
            number: Some("2.6TpmzzaQHgYr+mXjdGLQlg==|vT8VhfvMlWSCN9hxGYftZ5rjKRsZ9ofjdlUCx5Gubnk=|uoD3/GEQBWKKx2O+/YhZUCzVkfhm8rFK3sUEVV84mv8=".parse().unwrap()),
        };

        let copyable_fields = card.get_copyable_fields(None);

        assert_eq!(copyable_fields, vec![CopyableCipherFields::CardNumber]);
    }

    #[test]
    fn test_format_number_visa() {
        let card = CardView {
            number: Some("4111111111111111".to_string()),
            cardholder_name: None,
            exp_month: None,
            exp_year: None,
            code: None,
            brand: None,
        };

        assert_eq!(card.format_number(), Some("4111 1111 1111 1111".to_string()));
    }

    #[test]
    fn test_format_number_amex() {
        let card = CardView {
            number: Some("378282246310005".to_string()),
            cardholder_name: None,
            exp_month: None,
            exp_year: None,
            code: None,
            brand: None,
        };

        assert_eq!(card.format_number(), Some("3782 8224 6310 005".to_string()));
    }

    #[test]
    fn test_format_number_with_spaces() {
        let card = CardView {
            number: Some("4111 1111 1111 1111".to_string()),
            cardholder_name: None,
            exp_month: None,
            exp_year: None,
            code: None,
            brand: None,
        };

        assert_eq!(card.format_number(), Some("4111 1111 1111 1111".to_string()));
    }

    #[test]
    fn test_format_number_with_dashes() {
        let card = CardView {
            number: Some("4111-1111-1111-1111".to_string()),
            cardholder_name: None,
            exp_month: None,
            exp_year: None,
            code: None,
            brand: None,
        };

        assert_eq!(card.format_number(), Some("4111 1111 1111 1111".to_string()));
    }

    #[test]
    fn test_format_number_with_mixed_chars() {
        let card = CardView {
            number: Some("4111a1111b1111c1111".to_string()),
            cardholder_name: None,
            exp_month: None,
            exp_year: None,
            code: None,
            brand: None,
        };

        assert_eq!(card.format_number(), Some("4111 1111 1111 1111".to_string()));
    }

    #[test]
    fn test_format_number_short_number() {
        let card = CardView {
            number: Some("123".to_string()),
            cardholder_name: None,
            exp_month: None,
            exp_year: None,
            code: None,
            brand: None,
        };

        assert_eq!(card.format_number(), Some("123".to_string()));
    }

    #[test]
    fn test_format_number_none() {
        let card = CardView {
            number: None,
            cardholder_name: None,
            exp_month: None,
            exp_year: None,
            code: None,
            brand: None,
        };

        assert_eq!(card.format_number(), None);
    }

    #[test]
    fn test_format_number_empty() {
        let card = CardView {
            number: Some("".to_string()),
            cardholder_name: None,
            exp_month: None,
            exp_year: None,
            code: None,
            brand: None,
        };

        assert_eq!(card.format_number(), None);
    }

    #[test]
    fn test_format_number_no_digits() {
        let card = CardView {
            number: Some("abcd-efgh-ijkl".to_string()),
            cardholder_name: None,
            exp_month: None,
            exp_year: None,
            code: None,
            brand: None,
        };

        assert_eq!(card.format_number(), None);
    }

    #[test]
    fn test_format_number_by_brand_amex() {
        let card = CardView {
            number: Some("378282246310005".to_string()),
            brand: Some("Amex".to_string()),
            cardholder_name: None,
            exp_month: None,
            exp_year: None,
            code: None,
        };

        assert_eq!(card.format_number_by_brand(), Some("3782 822463 10005".to_string()));
    }

    #[test]
    fn test_format_number_by_brand_amex_american_express() {
        let card = CardView {
            number: Some("378282246310005".to_string()),
            brand: Some("American Express".to_string()),
            cardholder_name: None,
            exp_month: None,
            exp_year: None,
            code: None,
        };

        assert_eq!(card.format_number_by_brand(), Some("3782 822463 10005".to_string()));
    }

    #[test]
    fn test_format_number_by_brand_amex_wrong_length() {
        let card = CardView {
            number: Some("378282246310".to_string()), // Only 12 digits, should fall back
            brand: Some("Amex".to_string()),
            cardholder_name: None,
            exp_month: None,
            exp_year: None,
            code: None,
        };

        assert_eq!(card.format_number_by_brand(), Some("3782 8224 6310".to_string()));
    }

    #[test]
    fn test_format_number_by_brand_diners_club() {
        let card = CardView {
            number: Some("30569309025904".to_string()),
            brand: Some("Diners Club".to_string()),
            cardholder_name: None,
            exp_month: None,
            exp_year: None,
            code: None,
        };

        assert_eq!(card.format_number_by_brand(), Some("3056 930902 5904".to_string()));
    }

    #[test]
    fn test_format_number_by_brand_diners_club_alt_name() {
        let card = CardView {
            number: Some("30569309025904".to_string()),
            brand: Some("DinersClub".to_string()),
            cardholder_name: None,
            exp_month: None,
            exp_year: None,
            code: None,
        };

        assert_eq!(card.format_number_by_brand(), Some("3056 930902 5904".to_string()));
    }

    #[test]
    fn test_format_number_by_brand_diners_short_name() {
        let card = CardView {
            number: Some("30569309025904".to_string()),
            brand: Some("Diners".to_string()),
            cardholder_name: None,
            exp_month: None,
            exp_year: None,
            code: None,
        };

        assert_eq!(card.format_number_by_brand(), Some("3056 930902 5904".to_string()));
    }

    #[test]
    fn test_format_number_by_brand_diners_club_wrong_length() {
        let card = CardView {
            number: Some("30569309025".to_string()), // Only 11 digits, should fall back
            brand: Some("Diners Club".to_string()),
            cardholder_name: None,
            exp_month: None,
            exp_year: None,
            code: None,
        };

        assert_eq!(card.format_number_by_brand(), Some("3056 9309 025".to_string()));
    }

    #[test]
    fn test_format_number_by_brand_visa() {
        let card = CardView {
            number: Some("4111111111111111".to_string()),
            brand: Some("Visa".to_string()),
            cardholder_name: None,
            exp_month: None,
            exp_year: None,
            code: None,
        };

        assert_eq!(card.format_number_by_brand(), Some("4111 1111 1111 1111".to_string()));
    }

    #[test]
    fn test_format_number_by_brand_mastercard() {
        let card = CardView {
            number: Some("5555555555554444".to_string()),
            brand: Some("Mastercard".to_string()),
            cardholder_name: None,
            exp_month: None,
            exp_year: None,
            code: None,
        };

        assert_eq!(card.format_number_by_brand(), Some("5555 5555 5555 4444".to_string()));
    }

    #[test]
    fn test_format_number_by_brand_unknown() {
        let card = CardView {
            number: Some("4111111111111111".to_string()),
            brand: Some("Unknown Brand".to_string()),
            cardholder_name: None,
            exp_month: None,
            exp_year: None,
            code: None,
        };

        assert_eq!(card.format_number_by_brand(), Some("4111 1111 1111 1111".to_string()));
    }

    #[test]
    fn test_format_number_by_brand_no_brand() {
        let card = CardView {
            number: Some("4111111111111111".to_string()),
            brand: None,
            cardholder_name: None,
            exp_month: None,
            exp_year: None,
            code: None,
        };

        assert_eq!(card.format_number_by_brand(), Some("4111 1111 1111 1111".to_string()));
    }

    #[test]
    fn test_format_number_by_brand_case_insensitive() {
        let card = CardView {
            number: Some("378282246310005".to_string()),
            brand: Some("AMEX".to_string()), // Uppercase
            cardholder_name: None,
            exp_month: None,
            exp_year: None,
            code: None,
        };

        assert_eq!(card.format_number_by_brand(), Some("3782 822463 10005".to_string()));
    }

    #[test]
    fn test_format_number_by_brand_with_existing_formatting() {
        let card = CardView {
            number: Some("3782-822463-10005".to_string()), // With dashes
            brand: Some("Amex".to_string()),
            cardholder_name: None,
            exp_month: None,
            exp_year: None,
            code: None,
        };

        assert_eq!(card.format_number_by_brand(), Some("3782 822463 10005".to_string()));
    }

    #[test]
    fn test_format_number_by_brand_none() {
        let card = CardView {
            number: None,
            brand: Some("Amex".to_string()),
            cardholder_name: None,
            exp_month: None,
            exp_year: None,
            code: None,
        };

        assert_eq!(card.format_number_by_brand(), None);
    }

    #[test]
    fn test_format_number_by_brand_empty() {
        let card = CardView {
            number: Some("".to_string()),
            brand: Some("Amex".to_string()),
            cardholder_name: None,
            exp_month: None,
            exp_year: None,
            code: None,
        };

        assert_eq!(card.format_number_by_brand(), None);
    }
}
