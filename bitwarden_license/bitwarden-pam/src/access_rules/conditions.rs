use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

/// A single condition that gates access under an access rule.
///
/// Serialized using the server's wire format: an object tagged by a `kind` discriminant, e.g.
/// `{"kind":"human_approval"}` or `{"kind":"ip_allowlist","cidrs":["10.0.0.0/8"]}`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AccessCondition {
    /// Requires a human approval before access is granted.
    HumanApproval,
    /// Restricts access to a set of allow-listed CIDR ranges.
    IpAllowlist {
        /// The list of allowed CIDR ranges, e.g. `10.0.0.0/8`.
        cidrs: Vec<String>,
    },
    /// Any kind this SDK version doesn't model (e.g. the server's `time_of_day` condition).
    /// The whole object is preserved verbatim so list + enable/disable round-trips don't
    /// destroy conditions this SDK can't interpret.
    ///
    /// This also captures a known `kind` whose payload doesn't match the shape this SDK
    /// expects (e.g. an `ip_allowlist` condition missing its `cidrs` field) - the whole object
    /// is preserved verbatim rather than being rejected as a deserialization error.
    ///
    /// Known limitation: preservation applies to whole objects only. When a payload *does*
    /// match a modeled variant, any extra fields the server may add to that kind in the future
    /// are dropped on a deserialize→reserialize round trip (serde matches the tagged variant
    /// and discards unrecognized fields). Adding fields to a modeled kind therefore requires a
    /// matching SDK update; see the `extra_fields_on_known_kind_are_dropped` test.
    ///
    /// Note for TypeScript consumers: the generated type shows `kind: "unknown"`, but at
    /// runtime `kind` holds the server's actual discriminant string (e.g. `"time_of_day"`).
    /// Filter with a known-kind guard instead of matching on `"unknown"`.
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

        // Re-serializing must be lossless: comparing as `serde_json::Value` (rather than the
        // serialized string) because `serde_json::Value`'s underlying map does not guarantee to
        // preserve key insertion order without the `preserve_order` feature.
        let reserialized = serde_json::to_value(&parsed).unwrap();
        assert_eq!(reserialized, raw);
    }

    /// A known `kind` whose payload doesn't match the shape this SDK expects degrades to
    /// [`AccessCondition::Unknown`] rather than failing to deserialize. This is a consequence of
    /// `ip_allowlist` being declared after the `#[serde(untagged)]` catch-all in enum-variant
    /// order for internally tagged enums: serde first attempts every preceding tagged variant,
    /// and falls back to the untagged variant when none match - including when a *recognized* tag
    /// has an unexpected shape. This is the documented, intentional behavior for this type: it
    /// keeps list/round-trip operations lossless instead of hard-failing on a shape mismatch.
    #[test]
    fn malformed_known_kind_degrades_to_unknown() {
        let raw = json!({ "kind": "ip_allowlist" });

        let parsed: AccessCondition = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(parsed, AccessCondition::Unknown(raw));
    }

    /// Pins the documented limitation on [`AccessCondition::Unknown`]: a payload that matches a
    /// modeled variant has any extra/unrecognized fields silently dropped on a round trip -
    /// serde matches the tagged variant and never falls through to the untagged catch-all. If
    /// the server adds fields to a modeled kind, the SDK must be updated in lockstep.
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
