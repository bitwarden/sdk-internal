use bitwarden_vault::FieldType;
use credential_exchange_format::{
    EditableField, EditableFieldBoolean, EditableFieldConcealedString, EditableFieldCountryCode,
    EditableFieldDate, EditableFieldEmail, EditableFieldNumber, EditableFieldString,
    EditableFieldSubdivisionCode, EditableFieldType as CxfEditableFieldType, EditableFieldValue,
    EditableFieldWifiNetworkSecurityType, EditableFieldYearMonth, FieldType as CxfFieldType,
};

use crate::Field;

/// Helper function to create a Field from any EditableField type
pub(super) fn create_field<T>(field: &T, overridden_name: Option<impl Into<String>>) -> Field
where
    T: EditableFieldToField,
{
    let field_name = overridden_name
        .map(Into::into)
        .or_else(|| field.label().clone());

    Field {
        name: field_name,
        value: Some(field.field_value()),
        r#type: field.field_type() as u8,
        linked_id: None,
    }
}

/// Map a CXF [`FieldType`](CxfFieldType) to Bitwarden's narrower [`FieldType`].
///
/// CXF distinguishes many semantic field types (Date, YearMonth, CountryCode, …) but Bitwarden's
/// custom-fields model only has Text/Hidden/Boolean/Linked, so most CXF types collapse to Text.
fn cxf_to_bitwarden_field_type(cxf_type: &CxfFieldType) -> FieldType {
    match cxf_type {
        CxfFieldType::ConcealedString => FieldType::Hidden,
        CxfFieldType::Boolean => FieldType::Boolean,
        _ => FieldType::Text,
    }
}

/// Helper function to create an EditableField with common properties
pub(super) fn create_editable_field<T>(name: String, value: T) -> EditableField<T> {
    EditableField {
        id: None,
        label: Some(name),
        value: value.into(),
        extensions: None,
    }
}

/// Convert Bitwarden Field to CXF EditableFieldValue with proper type mapping
pub(super) fn field_to_editable_field_value(field: Field) -> Option<EditableFieldValue> {
    let name = field.name?;

    match field.r#type {
        x if x == FieldType::Text as u8 => field.value.map(|value| {
            EditableFieldValue::String(create_editable_field(name, EditableFieldString(value)))
        }),

        x if x == FieldType::Hidden as u8 => field.value.map(|value| {
            EditableFieldValue::ConcealedString(create_editable_field(
                name,
                EditableFieldConcealedString(value),
            ))
        }),

        x if x == FieldType::Boolean as u8 => field.value?.parse::<bool>().ok().map(|bool_value| {
            EditableFieldValue::Boolean(create_editable_field(
                name,
                EditableFieldBoolean(bool_value),
            ))
        }),

        x if x == FieldType::Linked as u8 => {
            let value = field
                .value
                .or_else(|| field.linked_id.map(|id| id.to_string()))?;
            Some(EditableFieldValue::String(create_editable_field(
                name,
                EditableFieldString(value),
            )))
        }

        _ => field.value.map(|value| {
            EditableFieldValue::String(create_editable_field(name, EditableFieldString(value)))
        }),
    }
}

/// Bitwarden-side string formatting for a CXF inner field type.
///
/// Defaults to the upstream `Into<String>` (which produces the spec wire form), so most types only
/// need a marker `impl InnerFieldType for X {}`. Override `to_field_value` only when the
/// vault-facing form should differ from the wire form (e.g. WiFi security types).
pub(super) trait InnerFieldType: CxfEditableFieldType + Clone + Into<String> {
    fn to_field_value(&self) -> String {
        self.clone().into()
    }
}

impl InnerFieldType for EditableFieldString {}
impl InnerFieldType for EditableFieldConcealedString {}
impl InnerFieldType for EditableFieldBoolean {}
impl InnerFieldType for EditableFieldDate {}
impl InnerFieldType for EditableFieldYearMonth {}
impl InnerFieldType for EditableFieldCountryCode {}
impl InnerFieldType for EditableFieldSubdivisionCode {}
impl InnerFieldType for EditableFieldEmail {}
impl InnerFieldType for EditableFieldNumber {}

impl InnerFieldType for EditableFieldWifiNetworkSecurityType {
    fn to_field_value(&self) -> String {
        use EditableFieldWifiNetworkSecurityType::*;
        match self {
            Unsecured => "Unsecured",
            WpaPersonal => "WPA Personal",
            Wpa2Personal => "WPA2 Personal",
            Wpa3Personal => "WPA3 Personal",
            Wep => "WEP",
            Other(s) => s,
            _ => "Unknown",
        }
        .to_string()
    }
}

/// Trait to convert CXF EditableField types to Bitwarden Field values and types.
///
/// The Bitwarden `FieldType` is derived from the value's runtime CXF type rather than from the
/// statically-expected `T`, so an unexpected payload (e.g. a `boolean` where we expected a
/// `string`) reports the type that actually arrived — keeping the resulting `Field` coherent.
pub(super) trait EditableFieldToField {
    fn field_type(&self) -> FieldType;
    fn field_value(&self) -> String;
    fn label(&self) -> &Option<String>;
}

impl<T> EditableFieldToField for EditableField<T>
where
    T: InnerFieldType,
{
    fn field_type(&self) -> FieldType {
        cxf_to_bitwarden_field_type(&self.value.field_type())
    }

    fn field_value(&self) -> String {
        match self.value.as_expected() {
            Ok(t) => t.to_field_value(),
            Err(unexpected) => unexpected.clone().into(),
        }
    }

    fn label(&self) -> &Option<String> {
        &self.label
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_field_string() {
        let editable_field = EditableField {
            id: None,
            label: None,
            value: EditableFieldString("Test Value".to_string()).into(),
            extensions: None,
        };

        let field = create_field(&editable_field, Some("Test Name"));

        assert_eq!(
            field,
            Field {
                name: Some("Test Name".to_string()),
                value: Some("Test Value".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            }
        );
    }

    #[test]
    fn test_create_field_concealed_string() {
        let editable_field = EditableField {
            id: None,
            label: None,
            value: EditableFieldConcealedString("Secret123".to_string()).into(),
            extensions: None,
        };

        let field = create_field(&editable_field, Some("Password"));

        assert_eq!(
            field,
            Field {
                name: Some("Password".to_string()),
                value: Some("Secret123".to_string()),
                r#type: FieldType::Hidden as u8,
                linked_id: None,
            }
        );
    }

    #[test]
    fn test_create_field_boolean_true() {
        let editable_field = EditableField {
            id: None,
            label: None,
            value: EditableFieldBoolean(true).into(),
            extensions: None,
        };

        let field = create_field(&editable_field, Some("Is Enabled"));

        assert_eq!(
            field,
            Field {
                name: Some("Is Enabled".to_string()),
                value: Some("true".to_string()),
                r#type: FieldType::Boolean as u8,
                linked_id: None,
            }
        );
    }

    #[test]
    fn test_create_field_boolean_false() {
        let editable_field = EditableField {
            id: None,
            label: None,
            value: EditableFieldBoolean(false).into(),
            extensions: None,
        };

        let field = create_field(&editable_field, Some("Is Hidden"));

        assert_eq!(
            field,
            Field {
                name: Some("Is Hidden".to_string()),
                value: Some("false".to_string()),
                r#type: FieldType::Boolean as u8,
                linked_id: None,
            }
        );
    }

    #[test]
    fn test_create_field_wifi_security() {
        let editable_field = EditableField {
            id: None,
            label: None,
            value: EditableFieldWifiNetworkSecurityType::Wpa3Personal.into(),
            extensions: None,
        };

        let field = create_field(&editable_field, Some("WiFi Security"));

        assert_eq!(
            field,
            Field {
                name: Some("WiFi Security".to_string()),
                value: Some("WPA3 Personal".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            }
        );
    }

    #[test]
    fn test_create_field_email() {
        let editable_field = EditableField {
            id: None,
            label: None,
            value: EditableFieldEmail("user@example.com".to_string()).into(),
            extensions: None,
        };

        let field = create_field(&editable_field, Some("Email"));

        assert_eq!(
            field,
            Field {
                name: Some("Email".to_string()),
                value: Some("user@example.com".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            }
        );
    }

    #[test]
    fn test_wifi_security_to_field_value() {
        assert_eq!(
            EditableFieldWifiNetworkSecurityType::Unsecured.to_field_value(),
            "Unsecured"
        );
        assert_eq!(
            EditableFieldWifiNetworkSecurityType::WpaPersonal.to_field_value(),
            "WPA Personal"
        );
        assert_eq!(
            EditableFieldWifiNetworkSecurityType::Wpa2Personal.to_field_value(),
            "WPA2 Personal"
        );
        assert_eq!(
            EditableFieldWifiNetworkSecurityType::Wpa3Personal.to_field_value(),
            "WPA3 Personal"
        );
        assert_eq!(
            EditableFieldWifiNetworkSecurityType::Wep.to_field_value(),
            "WEP"
        );
        assert_eq!(
            EditableFieldWifiNetworkSecurityType::Other("WPA2 Enterprise".to_string())
                .to_field_value(),
            "WPA2 Enterprise"
        );
    }

    #[test]
    fn test_create_field_date() {
        use chrono::NaiveDate;

        let editable_field = EditableField {
            id: None,
            label: None,
            value: EditableFieldDate(NaiveDate::from_ymd_opt(2025, 1, 15).unwrap()).into(),
            extensions: None,
        };

        let field = create_field(&editable_field, Some("Expiry Date".to_string()));

        assert_eq!(
            field,
            Field {
                name: Some("Expiry Date".to_string()),
                value: Some("2025-01-15".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            }
        );
    }

    #[test]
    fn test_create_field_year_month() {
        use chrono::Month;

        let editable_field = EditableField {
            id: None,
            label: None,
            value: EditableFieldYearMonth {
                year: 2025,
                month: Month::December,
            }
            .into(),
            extensions: None,
        };

        let field = create_field(&editable_field, Some("Card Expiry"));

        assert_eq!(
            field,
            Field {
                name: Some("Card Expiry".to_string()),
                value: Some("2025-12".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            }
        );
    }

    #[test]
    fn test_create_field_with_none_name_uses_label() {
        let editable_field = EditableField {
            id: None,
            label: Some("Label From Field".to_string()),
            value: EditableFieldString("Test Value".to_string()).into(),
            extensions: None,
        };

        let field = create_field(&editable_field, None::<String>);

        assert_eq!(
            field,
            Field {
                name: Some("Label From Field".to_string()),
                value: Some("Test Value".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            }
        );
    }

    /// When deserialization produces an `Expected::Unexpected` (e.g. a payload claims
    /// `fieldType: boolean` for a slot statically typed as `string`), `create_field` should
    /// preserve the raw string value AND report the actual incoming type.
    #[test]
    fn test_create_field_unexpected_type_reports_actual_type() {
        let editable_field: EditableField<EditableFieldString> =
            serde_json::from_value(serde_json::json!({
                "fieldType": "boolean",
                "value": "true",
            }))
            .unwrap();

        let field = create_field(&editable_field, Some("Mismatched"));

        assert_eq!(
            field,
            Field {
                name: Some("Mismatched".to_string()),
                value: Some("true".to_string()),
                r#type: FieldType::Boolean as u8,
                linked_id: None,
            }
        );
    }

    /// A `concealed-string` payload arriving in a `string` slot should surface as a Hidden field.
    #[test]
    fn test_create_field_unexpected_concealed_string_in_string_slot() {
        let editable_field: EditableField<EditableFieldString> =
            serde_json::from_value(serde_json::json!({
                "fieldType": "concealed-string",
                "value": "secret",
            }))
            .unwrap();

        let field = create_field(&editable_field, Some("Hidden Surprise"));

        assert_eq!(
            field,
            Field {
                name: Some("Hidden Surprise".to_string()),
                value: Some("secret".to_string()),
                r#type: FieldType::Hidden as u8,
                linked_id: None,
            }
        );
    }

    /// An `Unknown` CXF field type (e.g. one we don't model) should fall back to Text.
    #[test]
    fn test_create_field_unknown_cxf_type_falls_back_to_text() {
        let editable_field: EditableField<EditableFieldString> =
            serde_json::from_value(serde_json::json!({
                "fieldType": "some-future-type",
                "value": "future-value",
            }))
            .unwrap();

        let field = create_field(&editable_field, Some("Future"));

        assert_eq!(
            field,
            Field {
                name: Some("Future".to_string()),
                value: Some("future-value".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            }
        );
    }

    #[test]
    fn test_create_field_with_none_name_and_none_label() {
        let editable_field = EditableField {
            id: None,
            label: None,
            value: EditableFieldString("Test Value".to_string()).into(),
            extensions: None,
        };

        let field = create_field(&editable_field, None::<String>);

        assert_eq!(
            field,
            Field {
                name: None,
                value: Some("Test Value".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            }
        );
    }
}
