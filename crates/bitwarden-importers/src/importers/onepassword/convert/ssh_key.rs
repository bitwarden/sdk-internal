//! The SSH Key category.

use bitwarden_exporters::SshKey;
use bitwarden_ssh::import::import_key;

use super::{
    claimed::{Claimed, section_fields},
    value::{non_blank, render_value},
};
use crate::importers::onepassword::access::wire::VaultItemDetails;

/// Builds an SSH key from the first field that carries a usable one.
///
/// 1Password keeps the key material in the field's SSH key attributes, with the private key in
/// PKCS#8. Bitwarden expects OpenSSH, so `import_key` converts it and derives the public key and
/// fingerprint. A field is skipped when it has no private key, when the key cannot be read, or
/// when its value holds something other than the key. `None` means no field qualified.
pub(super) fn ssh_key(details: &VaultItemDetails) -> Option<(SshKey, Claimed)> {
    section_fields(details)
        .enumerate()
        .find_map(|(position, field)| {
            let attributes = field.attributes.as_ref()?.ssh_key.as_ref()?;
            let private_key = non_blank(attributes.private_key.as_deref()?)?;
            // Claiming the field would lose a value that does not repeat the key.
            if field
                .value
                .as_ref()
                .and_then(|value| render_value(field.kind.as_deref(), value))
                .is_some_and(|value| value != private_key)
            {
                return None;
            }
            // 1Password strips the passphrase when a key is added, so none is offered.
            let key = import_key(private_key.to_string(), None).ok()?;

            let key = SshKey {
                private_key: key.private_key,
                public_key: key.public_key,
                fingerprint: key.fingerprint,
            };
            let claimed = Claimed {
                designations: &[],
                fields: vec![position],
            };

            Some((key, claimed))
        })
}
