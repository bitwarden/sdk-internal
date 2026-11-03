use ldap3::result::LdapResult;

/// A password that must never appear in any output.
pub(super) const SENTINEL_PASSWORD: &str = "correct-horse-battery-staple";

pub(super) fn ldap_result(rc: u32, text: &str) -> LdapResult {
    LdapResult {
        rc,
        matched: "CN=svc-app,OU=Service Accounts,DC=corp,DC=example".to_string(),
        text: text.to_string(),
        refs: Vec::new(),
        ctrls: Vec::new(),
    }
}
