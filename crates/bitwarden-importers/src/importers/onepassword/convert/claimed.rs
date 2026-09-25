//! How an item's fields are addressed: walking them, reading one by name, and recording which a
//! category mapping already took.

use super::value::{non_blank, render_value};
use crate::importers::onepassword::access::wire::{VaultItemDetails, VaultItemSectionField};

/// What a category mapping already read, so the leftover pass does not repeat it.
#[derive(Default)]
pub(super) struct Claimed {
    /// Designations of consumed top-level fields.
    pub(super) designations: &'static [&'static str],
    /// Positions of consumed section fields, as [`section_fields`] numbers them. An id would not
    /// do: a mapping picks one field, and only its position says which.
    pub(super) fields: Vec<usize>,
}

impl Claimed {
    /// Reads the section field with this id and claims it, provided `read` makes something of it.
    /// A field `read` turns down stays for the leftover pass.
    pub(super) fn take<'a, T>(
        &mut self,
        details: &'a VaultItemDetails,
        id: &str,
        read: impl FnOnce(&'a VaultItemSectionField) -> Option<T>,
    ) -> Option<T> {
        let (position, field) = section_fields(details)
            .enumerate()
            .find(|(_, field)| field.id.as_deref() == Some(id))?;
        let value = read(field)?;
        self.fields.push(position);
        Some(value)
    }

    /// Reads the section field with this id as the text the leftover pass would have made of it,
    /// and claims it.
    pub(super) fn take_text(&mut self, details: &VaultItemDetails, id: &str) -> Option<String> {
        self.take(details, id, |field| {
            render_value(field.kind.as_deref(), field.value.as_ref()?)
        })
    }
}

/// Every section field of an item, flattened in the order 1Password sent them. A mapping and the
/// leftover pass walk this same sequence, so a position names one field for both.
pub(super) fn section_fields(
    details: &VaultItemDetails,
) -> impl Iterator<Item = &VaultItemSectionField> {
    details
        .sections
        .iter()
        .flatten()
        .flat_map(|section| section.fields.iter().flatten())
}

/// Reads one of the login fields 1Password tags with a `designation`. The designation is stable,
/// unlike the field's localized `name`.
pub(super) fn designation(details: &VaultItemDetails, designation: &str) -> Option<String> {
    details
        .fields
        .iter()
        .flatten()
        .find(|field| field.designation.as_deref() == Some(designation))
        .and_then(|field| field.value.as_deref())
        .and_then(non_blank)
        .map(str::to_string)
}
