use serde::{Deserialize, Serialize};

/// A single condition that gates access under an access rule.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[bitwarden_ffi::wasm_record]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AccessCondition {
    /// Requires a human approval before access is granted.
    HumanApproval,
    /// Restricts access to a set of allow-listed CIDR ranges.
    IpAllowlist {
        /// The list of allowed CIDR ranges, e.g. `10.0.0.0/8`.
        cidrs: Vec<String>,
    },
    /// A kind this SDK doesn't model, or a known kind with an unexpected shape, kept verbatim so
    /// round trips preserve it. At runtime `kind` holds the server's discriminant, not the
    /// generated type's `"unknown"`.
    #[serde(untagged)]
    Unknown(
        #[cfg_attr(feature = "wasm", tsify(type = "Record<string, unknown>"))] serde_json::Value,
    ),
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn human_approval_roundtrips() {
        let condition = AccessCondition::HumanApproval;
        let json = serde_json::to_value(&condition).unwrap();
        assert_eq!(json, json!({ "kind": "human_approval" }));

        let parsed: AccessCondition = serde_json::from_value(json).unwrap();
        assert_eq!(parsed, condition);
    }

    #[test]
    fn ip_allowlist_roundtrips() {
        let condition = AccessCondition::IpAllowlist {
            cidrs: vec!["10.0.0.0/8".to_string(), "2001:db8::/32".to_string()],
        };
        let json = serde_json::to_value(&condition).unwrap();
        assert_eq!(
            json,
            json!({ "kind": "ip_allowlist", "cidrs": ["10.0.0.0/8", "2001:db8::/32"] })
        );

        let parsed: AccessCondition = serde_json::from_value(json).unwrap();
        assert_eq!(parsed, condition);
    }

    #[test]
    fn unknown_kind_is_preserved_verbatim() {
        let raw = json!({
            "kind": "time_of_day",
            "tz": "UTC",
            "windows": [{ "start": "09:00", "end": "17:00" }],
        });

        let parsed: AccessCondition = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(parsed, AccessCondition::Unknown(raw.clone()));

        // Compared as `Value`, not as a string, since key order isn't preserved without
        // serde_json's `preserve_order` feature.
        let reserialized = serde_json::to_value(&parsed).unwrap();
        assert_eq!(reserialized, raw);
    }

    /// Serde falls back to the untagged [`AccessCondition::Unknown`] when a recognized tag has the
    /// wrong shape, so a malformed condition survives a round trip instead of failing the list.
    #[test]
    fn malformed_known_kind_degrades_to_unknown() {
        let raw = json!({ "kind": "ip_allowlist" });

        let parsed: AccessCondition = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(parsed, AccessCondition::Unknown(raw));
    }

    /// Extra fields on a modeled kind are dropped on a round trip, since serde matches the tagged
    /// variant and never reaches the catch-all. A server-side field addition needs an SDK update.
    #[test]
    fn extra_fields_on_known_kind_are_dropped() {
        let raw = json!({ "kind": "human_approval", "future_field": "not preserved" });
        let parsed: AccessCondition = serde_json::from_value(raw).unwrap();
        assert_eq!(parsed, AccessCondition::HumanApproval);
        assert_eq!(
            serde_json::to_value(&parsed).unwrap(),
            json!({ "kind": "human_approval" })
        );

        let raw = json!({ "kind": "ip_allowlist", "cidrs": ["10.0.0.0/8"], "extra": "dropped" });
        let parsed: AccessCondition = serde_json::from_value(raw).unwrap();
        assert_eq!(
            serde_json::to_value(&parsed).unwrap(),
            json!({ "kind": "ip_allowlist", "cidrs": ["10.0.0.0/8"] })
        );
    }
}
