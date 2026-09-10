//! The leftover pass: every field a category mapping did not claim becomes a custom field, so no
//! part of an item is lost.

use bitwarden_exporters::Field;

use super::{
    claimed::{Claimed, section_fields},
    value::{non_blank, render_value},
};
use crate::importers::onepassword::access::wire::VaultItemDetails;

/// Bitwarden's custom field types.
pub(super) const TEXT_FIELD: u8 = 0;
pub(super) const HIDDEN_FIELD: u8 = 1;

/// Collects every field a category mapping did not claim, so no part of an item is lost.
///
/// Fields without a value are skipped: 1Password stores its whole category template on every item,
/// so most of them are empty.
pub(super) fn fields_from_details(details: &VaultItemDetails, claimed: &Claimed) -> Vec<Field> {
    let mut fields = Vec::new();
    // A mapping reads the first field carrying a designation, so the claim is spent on that one
    // occurrence; should an item repeat a designation, the repeat still becomes a custom field.
    let mut designations = claimed.designations.to_vec();

    for field in details.fields.iter().flatten() {
        let designation = field.designation.as_deref().unwrap_or_default();
        if let Some(claim) = designations.iter().position(|taken| *taken == designation) {
            designations.remove(claim);
            continue;
        }

        push_field(
            &mut fields,
            field
                .name
                .as_deref()
                .and_then(non_blank)
                .or(non_blank(designation)),
            field
                .value
                .as_deref()
                .and_then(non_blank)
                .map(str::to_string),
            field.kind.as_deref() == Some("P"),
        );
    }

    for (position, field) in section_fields(details).enumerate() {
        if claimed.fields.contains(&position) {
            continue;
        }

        let name = field
            .name
            .as_deref()
            .and_then(non_blank)
            .or(field.id.as_deref().and_then(non_blank));
        let hidden = field.kind.as_deref() == Some("concealed");
        let Some(value) = field.value.as_ref() else {
            continue;
        };

        match (field.kind.as_deref(), value) {
            // An attachment's value is the envelope that unwraps the stored file, encryption keys
            // included. The file cannot come along, so only its name does. A `file` field holding
            // anything but an envelope carries no attachment and falls through.
            (Some("file"), serde_json::Value::Object(_)) => push_field(
                &mut fields,
                name,
                Some(format!("<attachment: {}>", attachment_name(value, name))),
                false,
            ),
            // An address has no single text form, so each part it fills in becomes its own field.
            (Some("address"), serde_json::Value::Object(parts)) => {
                for (part, value) in parts {
                    push_field(&mut fields, Some(part), render_value(None, value), hidden);
                }
            }
            _ => push_field(
                &mut fields,
                name,
                render_value(field.kind.as_deref(), value),
                hidden,
            ),
        }
    }

    fields
}

fn attachment_name<'a>(value: &'a serde_json::Value, fallback: Option<&'a str>) -> &'a str {
    value
        .get("fileName")
        .and_then(serde_json::Value::as_str)
        .and_then(non_blank)
        .or(fallback)
        .unwrap_or("unnamed")
}

/// A field is hidden when 1Password treats its value as a secret. The `guarded` attribute is not
/// that signal: the Identity template sets it on plain fields such as the first name.
fn push_field(fields: &mut Vec<Field>, name: Option<&str>, value: Option<String>, hidden: bool) {
    let Some(value) = value else {
        return;
    };

    fields.push(Field {
        name: name.map(str::to_string),
        value: Some(value),
        r#type: if hidden { HIDDEN_FIELD } else { TEXT_FIELD },
        linked_id: None,
    });
}
