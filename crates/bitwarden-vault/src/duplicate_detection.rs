use std::{collections::HashMap, str::FromStr};

use bitwarden_crypto::EncString;
use url::Url;

use crate::{cipher::login::DuplicateUriMatchType, Cipher};

fn normalize_name_for_matching(s: &str) -> String {
    // currently only removes internal and external whitespace
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

fn normalize_uri_for_matching(uri: &str, strategy: &DuplicateUriMatchType) -> Option<String> {
    match strategy {
        DuplicateUriMatchType::Domain => Url::parse(uri).ok().and_then(|url| {
            url.host_str()
                .and_then(|hostname| psl::domain_str(hostname).map(|domain| domain.to_string()))
        }),
        DuplicateUriMatchType::Hostname => Url::parse(uri)
            .ok()
            .and_then(|url| url.host_str().map(|hostname| hostname.to_string())),
        DuplicateUriMatchType::Host => Url::parse(uri).ok().map(|url| {
            let hostname = url.host_str().map(|hostname| hostname.to_string());
            let default_port = if url.scheme() == "http" { 80 } else { 443 };
            format!(
                "{}:{}",
                hostname.unwrap_or_default(),
                url.port().unwrap_or(default_port)
            )
        }),
        DuplicateUriMatchType::Exact => Some(uri.to_string()),
    }
}

fn find_duplicates<'a>(ciphers: &'a [Cipher], strategy: DuplicateUriMatchType) -> Vec<&'a Cipher> {
    let mut counts: HashMap<String, Vec<&'a Cipher>> = HashMap::new();

    for cipher in ciphers.iter() {
        if let Some(login) = cipher.login.as_ref() {
            // for login ciphers, match on username and uri
            if let Some(uris) = login.uris.as_ref() {
                let empty_string =
                    EncString::from_str("").expect("Failed to create empty EncString");
                let username = login.username.as_ref().unwrap_or(&empty_string).to_string();
                for login_uri_view in uris.iter() {
                    if let Some(uri) = login_uri_view.uri.as_ref() {
                        if let Some(normalized_uri) =
                            normalize_uri_for_matching(&uri.to_string(), &strategy)
                        {
                            let key = format!("USERNAME+URI:{}:{}", username, normalized_uri);
                            counts.entry(key).or_default().push(cipher);
                        }
                    }
                }
            }
        } else {
            // if not login, match on cipher name
            let name = normalize_name_for_matching(&cipher.name.to_string());
            let key = format!("NAME:{}", name);
            counts.entry(key).or_default().push(cipher);
        }
    }

    counts
        .into_values()
        .filter(|ciphers| ciphers.len() >= 2)
        .flatten()
        .collect()
}
