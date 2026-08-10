//! Wire DTOs to the native model: the parsing that turns a decrypted item into an `Item`.

use super::{
    model::{Field, Item, ItemCategory, Otp, PastPassword, SshKey, Url},
    wire::{SshKeyType, VaultItemDetails, VaultItemOverview, VaultItemSectionField},
};

impl Item {
    /// Builds a native item from its decrypted overview and details. Every category keeps its full
    /// set of fields, sections, OTPs, and URLs; login-style categories additionally surface their
    /// username/password/url, and SSH keys surface their raw key.
    pub(crate) fn from_wire(
        id: String,
        category: ItemCategory,
        overview: &VaultItemOverview,
        details: &VaultItemDetails,
    ) -> Item {
        // Logins and servers are the "account" categories that expose a username/password/url.
        let is_account = matches!(category, ItemCategory::Login | ItemCategory::Server);
        let url = match &category {
            ItemCategory::Login => overview.url.clone().unwrap_or_default(),
            ItemCategory::Server => find_field(details, "URL"),
            _ => String::new(),
        };
        let (username, password) = if is_account {
            (
                find_field(details, "username"),
                find_field(details, "password"),
            )
        } else {
            // A Password item has no `fields`; its secret sits at the top of the details instead.
            (String::new(), details.password.clone().unwrap_or_default())
        };
        let ssh_key = if matches!(category, ItemCategory::SshKey) {
            parse_ssh_key(details)
        } else {
            None
        };

        Item {
            id,
            category,
            title: overview.title.clone().unwrap_or_default(),
            additional_info: overview.ainfo.clone().unwrap_or_default(),
            note: details.note.clone().unwrap_or_default(),
            username,
            password,
            url,
            urls: parse_urls(overview),
            otps: parse_otps(details),
            fields: parse_fields(details),
            ssh_key,
            tags: overview.tags.clone().unwrap_or_default(),
            password_history: parse_password_history(details),
        }
    }
}

/// Keeps only the entries that carry a password; the timestamp defaults to 0 when absent.
fn parse_password_history(details: &VaultItemDetails) -> Vec<PastPassword> {
    details
        .password_history
        .iter()
        .flatten()
        .filter_map(|entry| {
            entry.value.as_ref().map(|password| PastPassword {
                password: password.clone(),
                changed_at: entry.time.unwrap_or_default(),
            })
        })
        .collect()
}

/// Looks up a value by its designation (login fields) or, failing that, its name (section fields).
fn find_field(details: &VaultItemDetails, name: &str) -> String {
    for field in details.fields.iter().flatten() {
        if field.designation.as_deref() == Some(name) {
            return field.value.clone().unwrap_or_default();
        }
    }
    for section in details.sections.iter().flatten() {
        for field in section.fields.iter().flatten() {
            if field.name.as_deref() == Some(name) {
                return field_value(field);
            }
        }
    }
    String::new()
}

/// Collects the websites listed in an item's overview.
fn parse_urls(overview: &VaultItemOverview) -> Vec<Url> {
    overview
        .urls
        .iter()
        .flatten()
        .map(|url| Url {
            label: url.name.clone().unwrap_or_default(),
            value: url.url.clone().unwrap_or_default(),
        })
        .collect()
}

/// Collects TOTP fields: concealed section fields whose id starts with `TOTP_`.
fn parse_otps(details: &VaultItemDetails) -> Vec<Otp> {
    let mut otps = Vec::new();
    for section in details.sections.iter().flatten() {
        for field in section.fields.iter().flatten() {
            if field.kind.as_deref() == Some("concealed")
                && field
                    .id
                    .as_deref()
                    .is_some_and(|id| id.starts_with("TOTP_"))
            {
                otps.push(Otp {
                    label: field.name.clone().unwrap_or_default(),
                    secret: field_value(field),
                    section: section.name.clone().unwrap_or_default(),
                });
            }
        }
    }
    otps
}

/// Flattens every section field, preserving its section, kind, and guarded flag.
fn parse_fields(details: &VaultItemDetails) -> Vec<Field> {
    let mut fields = Vec::new();
    for section in details.sections.iter().flatten() {
        for field in section.fields.iter().flatten() {
            fields.push(Field {
                id: field.id.clone().unwrap_or_default(),
                label: field.name.clone().unwrap_or_default(),
                value: field_value(field),
                kind: field.kind.clone().unwrap_or_default(),
                section: section.name.clone().unwrap_or_default(),
                guarded: field
                    .attributes
                    .as_ref()
                    .and_then(|a| a.guarded.as_deref())
                    .is_some_and(|guarded| guarded == "yes"),
            });
        }
    }
    fields
}

/// Renders a section field's polymorphic value: JSON strings pass through, anything else becomes
/// compact JSON.
fn field_value(field: &VaultItemSectionField) -> String {
    match &field.value {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
        None => String::new(),
    }
}

/// Extracts the raw SSH key from the first field of the first section, where 1Password stores it.
/// Lenient on purpose: a malformed item yields `None` rather than failing the whole download.
fn parse_ssh_key(details: &VaultItemDetails) -> Option<SshKey> {
    let field = details
        .sections
        .as_ref()?
        .first()?
        .fields
        .as_ref()?
        .first()?;
    let attributes = field.attributes.as_ref()?.ssh_key.as_ref()?;
    Some(SshKey {
        private_key: attributes.private_key.clone().unwrap_or_default(),
        public_key: attributes.public_key.clone().unwrap_or_default(),
        fingerprint: attributes.fingerprint.clone().unwrap_or_default(),
        key_type: format_key_type(attributes.key_type.as_ref()),
    })
}

/// Formats an SSH key type as `type`, or `type-bits` for RSA.
fn format_key_type(key_type: Option<&SshKeyType>) -> String {
    match key_type {
        None => String::new(),
        Some(key_type) if key_type.bits == 0 => key_type.kind.clone(),
        Some(key_type) => format!("{}-{}", key_type.kind, key_type.bits),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_wire_takes_a_password_item_secret_from_the_details() {
        // A Password item carries no `fields`; the secret and the tags come from elsewhere.
        let overview: VaultItemOverview =
            serde_json::from_str(r#"{"title":"WiFi","tags":["home"]}"#).expect("valid overview");
        let details: VaultItemDetails = serde_json::from_str(
            r#"{"password":"Sup3rS3cret!","notesPlain":"",
                "passwordHistory":[{"value":"old-one","time":1694692860}]}"#,
        )
        .expect("valid details");

        let item = Item::from_wire("id".into(), ItemCategory::Password, &overview, &details);

        assert_eq!(item.password, "Sup3rS3cret!");
        assert_eq!(item.username, "");
        assert_eq!(item.tags, vec!["home"]);
        assert_eq!(item.password_history.len(), 1);
        assert_eq!(item.password_history[0].password, "old-one");
        assert_eq!(item.password_history[0].changed_at, 1694692860);
    }

    #[test]
    fn from_wire_extracts_login_fields() {
        let overview: VaultItemOverview = serde_json::from_str(
            r#"{"title":"GitHub","ainfo":"octocat","url":"https://github.com",
                "URLs":[{"l":"website","u":"https://github.com"},{"u":"https://gist.github.com"}]}"#,
        )
        .expect("valid overview");
        let details: VaultItemDetails = serde_json::from_str(
            r#"{"notesPlain":"my note","fields":[
                {"name":"username","value":"octocat","designation":"username"},
                {"name":"password","value":"hunter2","designation":"password"}]}"#,
        )
        .expect("valid details");

        let item = Item::from_wire("id1".into(), ItemCategory::Login, &overview, &details);

        assert_eq!(item.title, "GitHub");
        assert_eq!(item.additional_info, "octocat");
        assert_eq!(item.note, "my note");
        assert_eq!(item.username, "octocat");
        assert_eq!(item.password, "hunter2");
        assert_eq!(item.url, "https://github.com");
        assert_eq!(item.urls.len(), 2);
        assert_eq!(
            item.urls[0],
            Url {
                label: "website".into(),
                value: "https://github.com".into()
            }
        );
        assert_eq!(item.urls[1].label, "");
    }

    #[test]
    fn from_wire_parses_sections_fields_and_otps() {
        let details: VaultItemDetails = serde_json::from_str(include_str!(
            "resources/vault-item-with-lots-of-fields.json"
        ))
        .expect("valid fixture");
        let overview: VaultItemOverview = serde_json::from_str("{}").expect("empty overview");

        let item = Item::from_wire("id2".into(), ItemCategory::Login, &overview, &details);

        // Two sections of six fields each are flattened, with four TOTP fields pulled out.
        assert_eq!(item.fields.len(), 12);
        assert_eq!(item.otps.len(), 4);
        assert_eq!(
            item.otps[0],
            Otp {
                label: "otp1".into(),
                secret: "blahblahblah".into(),
                section: "Section1".into()
            }
        );

        // Polymorphic values: object -> compact JSON, number -> string, missing -> empty.
        let value = |label: &str| {
            item.fields
                .iter()
                .find(|f| f.label == label)
                .map(|f| f.value.as_str())
        };
        assert_eq!(value("sign in with1"), Some(r#"{"provider":"github"}"#));
        assert_eq!(value("date1"), Some("1694692860"));
        assert_eq!(value("date2"), Some(""));
        assert_eq!(value("mo/ye"), Some("202112"));

        // The section label comes from the section's title.
        assert_eq!(item.fields[0].section, "Section1");
        // The designation fields in this fixture are empty.
        assert_eq!(item.username, "");
        assert_eq!(item.password, "");
    }

    #[test]
    fn maps_template_ids_to_categories() {
        assert_eq!(ItemCategory::from_template_id("001"), ItemCategory::Login);
        assert_eq!(
            ItemCategory::from_template_id("002"),
            ItemCategory::CreditCard
        );
        assert_eq!(
            ItemCategory::from_template_id("004"),
            ItemCategory::Identity
        );
        assert_eq!(ItemCategory::from_template_id("110"), ItemCategory::Server);
        assert_eq!(ItemCategory::from_template_id("114"), ItemCategory::SshKey);
        assert_eq!(
            ItemCategory::from_template_id("777"),
            ItemCategory::Unknown("777".into())
        );
        assert_eq!(
            ItemCategory::Unknown("777".into()).to_string(),
            "Unknown(777)"
        );
    }

    #[test]
    fn non_login_item_preserves_all_fields() {
        let overview: VaultItemOverview =
            serde_json::from_str(r#"{"title":"My Card"}"#).expect("valid overview");
        let details: VaultItemDetails = serde_json::from_str(
            r#"{"sections":[{"title":"","fields":[
                {"t":"cardholder name","v":"Jane Doe","k":"string","n":"cardholder"},
                {"t":"number","v":"4111111111111111","k":"creditCardNumber","n":"ccnum"}]}]}"#,
        )
        .expect("valid details");

        let item = Item::from_wire("c1".into(), ItemCategory::CreditCard, &overview, &details);

        assert_eq!(item.category, ItemCategory::CreditCard);
        assert_eq!(item.title, "My Card");
        // Username/password are only surfaced for login-style categories.
        assert_eq!(item.username, "");
        assert_eq!(item.password, "");
        assert_eq!(item.fields.len(), 2);
        assert_eq!(item.fields[1].label, "number");
        assert_eq!(item.fields[1].value, "4111111111111111");
    }

    #[test]
    fn server_extracts_url_from_a_section_field() {
        let overview: VaultItemOverview = serde_json::from_str("{}").expect("empty overview");
        let details: VaultItemDetails = serde_json::from_str(
            r#"{"sections":[{"title":"","fields":[
                {"t":"URL","v":"https://server.example.com","k":"string","n":"url"}]}],
                "fields":[{"name":"username","value":"admin","designation":"username"}]}"#,
        )
        .expect("valid details");

        let item = Item::from_wire("s1".into(), ItemCategory::Server, &overview, &details);

        assert_eq!(item.url, "https://server.example.com");
        assert_eq!(item.username, "admin");
    }

    #[test]
    fn ssh_key_attributes_are_parsed() {
        let overview: VaultItemOverview =
            serde_json::from_str(r#"{"title":"my key"}"#).expect("valid overview");
        let details: VaultItemDetails = serde_json::from_str(
            r#"{"sections":[{"fields":[{"n":"private_key","k":"sshKey","t":"private key",
                "a":{"sshKeyAttributes":{
                    "privateKey":"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----",
                    "publicKey":"ssh-ed25519 AAAAC3Nz",
                    "fingerprint":"SHA256:abcdef",
                    "keyType":{"t":"ed25519"}}}}]}]}"#,
        )
        .expect("valid details");

        let item = Item::from_wire("k1".into(), ItemCategory::SshKey, &overview, &details);
        let ssh = item.ssh_key.expect("ssh key present");

        assert_eq!(ssh.key_type, "ed25519");
        assert_eq!(ssh.public_key, "ssh-ed25519 AAAAC3Nz");
        assert_eq!(ssh.fingerprint, "SHA256:abcdef");
        assert!(ssh.private_key.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn rsa_ssh_key_type_includes_bit_length() {
        let key_type = SshKeyType {
            kind: "rsa".into(),
            bits: 4096,
        };
        assert_eq!(format_key_type(Some(&key_type)), "rsa-4096");
    }
}
