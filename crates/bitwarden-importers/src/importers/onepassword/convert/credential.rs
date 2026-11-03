//! The categories built around a credential, all of which land on a login. Each keeps the same
//! three slots under ids of its own, and everything else rides along as a custom field.

use bitwarden_exporters::Login;

use super::{
    claimed::Claimed,
    login::{first_totp, login_uris, website_addresses},
    value::non_blank,
};
use crate::importers::onepassword::access::wire::{VaultItemDetails, VaultItemOverview};

/// The section field ids a category uses for the username, the password and the address the
/// credential belongs to. A slot the category does not have is `None`.
pub(super) struct CredentialFields {
    username: Option<&'static str>,
    password: Option<&'static str>,
    address: Option<&'static str>,
}

pub(super) const SERVER_FIELDS: CredentialFields = CredentialFields {
    username: Some("username"),
    password: Some("password"),
    address: Some("url"),
};

pub(super) const DATABASE_FIELDS: CredentialFields = CredentialFields {
    username: Some("username"),
    password: Some("password"),
    address: Some("hostname"),
};

pub(super) const API_CREDENTIAL_FIELDS: CredentialFields = CredentialFields {
    username: Some("username"),
    password: Some("credential"),
    address: Some("hostname"),
};

pub(super) const EMAIL_ACCOUNT_FIELDS: CredentialFields = CredentialFields {
    username: Some("pop_username"),
    password: Some("pop_password"),
    address: Some("provider_website"),
};

/// A router has no account name, and its own password is the base station's; the wireless network
/// key is a separate field and stays with the rest.
pub(super) const WIRELESS_ROUTER_FIELDS: CredentialFields = CredentialFields {
    username: None,
    password: Some("password"),
    address: Some("server"),
};

const PASSWORD_FIELDS: CredentialFields = CredentialFields {
    username: None,
    password: None,
    address: None,
};

/// Maps a category that carries a credential onto a login. The item's website addresses come
/// first; the category's own address follows, so a server or database is reachable by its host.
pub(super) fn credential_login(
    overview: &VaultItemOverview,
    details: &VaultItemDetails,
    ids: &CredentialFields,
) -> (Login, Claimed) {
    let mut claimed = Claimed::default();
    let mut take = |id: Option<&str>| claimed.take_text(details, id?);
    let username = take(ids.username);
    let password = take(ids.password);
    let address = take(ids.address);

    let (totp_position, totp) = first_totp(details).unzip();
    claimed.fields.extend(totp_position);

    let mut login = Login {
        username,
        password,
        login_uris: login_uris(website_addresses(overview).chain(address.as_deref())),
        totp,
        fido2_credentials: None,
    };
    login.sanitize_uris();

    (login, claimed)
}

/// A Password item keeps its secret in the details rather than in a field, and has no username or
/// address of its own.
pub(super) fn password(
    overview: &VaultItemOverview,
    details: &VaultItemDetails,
) -> (Login, Claimed) {
    let (mut login, claimed) = credential_login(overview, details, &PASSWORD_FIELDS);
    login.password = details
        .password
        .as_deref()
        .and_then(non_blank)
        .map(str::to_string);

    (login, claimed)
}
