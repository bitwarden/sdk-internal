//! Normalization of an administrator's settings object into a [`ManagementProfile`].
//!
//! Every client passes the raw JSON its host's Unified Endpoint Management channel supplied, so
//! all clients derive the same dotted keys from the same input. The keys and encoded values match
//! what `JSON.parse` followed by `JSON.stringify` produces in JavaScript, because the browser
//! extension's `chrome.storage.managed` values were flattened that way before normalization moved
//! into the SDK, and consumers on every client compare against those strings.

use std::collections::HashMap;

use bitwarden_managed_settings_types::{ManagedSettingsError, ManagementProfile};
use serde_json::{Map, Number, Value};

/// Schema version stamped onto every profile built from JSON. Bump it when the dotted-key
/// namespace changes incompatibly.
pub(crate) const MANAGEMENT_PROFILE_VERSION: u32 = 1;

/// Builds a profile from an administrator's settings object, stamped with the current time.
///
/// Rejects input that is not valid JSON, and input whose top level is not an object, so a caller
/// never applies a fragment of a malformed value.
pub(crate) fn profile_from_json(json: &str) -> Result<ManagementProfile, ManagedSettingsError> {
    let value: Value = serde_json::from_str(json)
        .map_err(|error| ManagedSettingsError::InvalidJson(error.to_string()))?;

    let Value::Object(source) = value else {
        return Err(ManagedSettingsError::NotAnObject(
            json_type_name(&value).to_owned(),
        ));
    };

    Ok(ManagementProfile {
        version: MANAGEMENT_PROFILE_VERSION,
        updated_at: now_seconds(),
        settings: flatten_settings(&source),
    })
}

/// Flattens a nested settings object into dotted keys with JSON-encoded leaves. For example
/// `{ "environment": { "base": "https://vault" } }` becomes the single entry `environment.base`
/// -> `"\"https://vault\""`. Arrays and primitives are leaves and are encoded whole; only objects
/// are descended into. An empty object produces no key, because a dotted key cannot address a
/// namespace.
///
/// A source key that already contains a `.` is emitted verbatim, so `{ "a.b": 1 }` and
/// `{ "a": { "b": 1 } }` collapse to one key, and the entry visited last wins. No escape syntax is
/// defined, because no Bitwarden key has a dot inside a segment.
pub(crate) fn flatten_settings(source: &Map<String, Value>) -> HashMap<String, String> {
    let mut settings = HashMap::new();
    visit(source, "", &mut settings);
    settings
}

fn visit(source: &Map<String, Value>, prefix: &str, settings: &mut HashMap<String, String>) {
    for (key, value) in js_property_order(source) {
        let dotted_key = if prefix.is_empty() {
            key.to_owned()
        } else {
            format!("{prefix}.{key}")
        };

        match value {
            Value::Object(namespace) => visit(namespace, &dotted_key, settings),
            leaf => {
                settings.insert(dotted_key, js_stringify(leaf));
            }
        }
    }
}

/// The entries of `object` in the order JavaScript enumerates an object's own properties: keys
/// that are array indices first, in ascending numeric order, then every other key in the order the
/// map yields it. That order is the source order when `serde_json` preserves insertion order, and
/// alphabetical order otherwise.
fn js_property_order(object: &Map<String, Value>) -> Vec<(&str, &Value)> {
    let mut indices: Vec<(u32, &str, &Value)> = Vec::new();
    let mut others: Vec<(&str, &Value)> = Vec::new();

    for (key, value) in object {
        match array_index(key) {
            Some(index) => indices.push((index, key, value)),
            None => others.push((key, value)),
        }
    }

    indices.sort_by_key(|(index, _, _)| *index);
    indices
        .into_iter()
        .map(|(_, key, value)| (key, value))
        .chain(others)
        .collect()
}

/// The numeric value of `key` when JavaScript treats it as an array index: the canonical decimal
/// form of an integer below `2^32 - 1`, with no sign and no leading zero.
fn array_index(key: &str) -> Option<u32> {
    if key.is_empty() || (key.len() > 1 && key.starts_with('0')) {
        return None;
    }
    if !key.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    key.parse::<u32>().ok().filter(|index| *index < u32::MAX)
}

/// Encodes `value` the way `JSON.stringify` encodes the result of `JSON.parse` on the same input.
fn js_stringify(value: &Value) -> String {
    let mut out = String::new();
    write_js_json(value, &mut out);
    out
}

fn write_js_json(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(boolean) => out.push_str(if *boolean { "true" } else { "false" }),
        Value::Number(number) => out.push_str(&js_number(number)),
        Value::String(string) => {
            out.push_str(&serde_json::to_string(string).expect("a string always serializes"))
        }
        Value::Array(items) => {
            out.push('[');
            for (position, item) in items.iter().enumerate() {
                if position > 0 {
                    out.push(',');
                }
                write_js_json(item, out);
            }
            out.push(']');
        }
        Value::Object(object) => {
            out.push('{');
            for (position, (key, item)) in js_property_order(object).into_iter().enumerate() {
                if position > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).expect("a string always serializes"));
                out.push(':');
                write_js_json(item, out);
            }
            out.push('}');
        }
    }
}

/// The largest integer JavaScript represents exactly, `2^53 - 1`.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Formats a number the way JavaScript's `Number.prototype.toString` does after `JSON.parse` has
/// read it into a double. An integer beyond the safe range is rounded to the nearest double, as
/// `JSON.parse` would round it.
fn js_number(number: &Number) -> String {
    if let Some(unsigned) = number.as_u64()
        && unsigned <= MAX_SAFE_INTEGER
    {
        return unsigned.to_string();
    }
    if let Some(signed) = number.as_i64()
        && signed.unsigned_abs() <= MAX_SAFE_INTEGER
    {
        return signed.to_string();
    }
    js_double(number.as_f64().unwrap_or(f64::NAN))
}

fn js_double(double: f64) -> String {
    // `JSON.stringify` writes every non-finite number as `null`. A JSON number literal never
    // parses to one, so this only guards the conversion above.
    if !double.is_finite() {
        return "null".to_owned();
    }
    if double == 0.0 {
        // Covers negative zero, which JavaScript prints without a sign.
        return "0".to_owned();
    }

    let magnitude = double.abs();
    if (1e-6..1e21).contains(&magnitude) {
        // Rust's `Display` for `f64` prints the shortest digits that round-trip, without an
        // exponent, which is what JavaScript prints in this range.
        return format!("{double}");
    }

    // Outside that range JavaScript uses an exponent with an explicit sign, such as `1e+21` and
    // `1.5e-8`. Rust's `LowerExp` prints the same shortest digits, without the `+`.
    let formatted = format!("{double:e}");
    match formatted.split_once('e') {
        Some((mantissa, exponent)) if !exponent.starts_with('-') => {
            format!("{mantissa}e+{exponent}")
        }
        _ => formatted,
    }
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

fn now_seconds() -> i64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flatten(json: &str) -> HashMap<String, String> {
        let Value::Object(source) = serde_json::from_str(json).expect("test input is valid JSON")
        else {
            panic!("test input is an object");
        };
        flatten_settings(&source)
    }

    fn settings(entries: &[(&str, &str)]) -> HashMap<String, String> {
        entries
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    }

    #[test]
    fn encodes_a_string_leaf_as_its_json_representation() {
        assert_eq!(
            flatten(r#"{ "value": "https://vault.example.com" }"#),
            settings(&[("value", r#""https://vault.example.com""#)])
        );
    }

    #[test]
    fn encodes_a_number_leaf_as_its_json_representation() {
        assert_eq!(flatten(r#"{ "value": 20 }"#), settings(&[("value", "20")]));
    }

    #[test]
    fn encodes_a_boolean_leaf_as_its_json_representation() {
        assert_eq!(
            flatten(r#"{ "value": true }"#),
            settings(&[("value", "true")])
        );
    }

    #[test]
    fn keeps_a_null_leaf_because_presence_means_the_value_is_forced() {
        assert_eq!(
            flatten(r#"{ "value": null }"#),
            settings(&[("value", "null")])
        );
    }

    #[test]
    fn joins_a_nested_objects_keys_with_a_dot() {
        assert_eq!(
            flatten(r#"{ "environment": { "base": "https://vault.example.com" } }"#),
            settings(&[("environment.base", r#""https://vault.example.com""#)])
        );
    }

    #[test]
    fn joins_keys_across_multiple_levels_of_nesting() {
        assert_eq!(
            flatten(r#"{ "generator": { "password": { "length": 20 } } }"#),
            settings(&[("generator.password.length", "20")])
        );
    }

    #[test]
    fn encodes_an_array_leaf_as_one_json_value_rather_than_indexed_keys() {
        assert_eq!(
            flatten(r#"{ "regions": ["us", "eu"] }"#),
            settings(&[("regions", r#"["us","eu"]"#)])
        );
    }

    #[test]
    fn omits_an_empty_object() {
        assert_eq!(flatten(r#"{ "environment": {} }"#), settings(&[]));
    }

    #[test]
    fn returns_no_settings_for_an_empty_source() {
        assert_eq!(flatten("{}"), settings(&[]));
    }

    #[test]
    fn emits_a_source_key_that_already_contains_a_dot_verbatim() {
        assert_eq!(
            flatten(r#"{ "environment.base": "https://vault.example.com" }"#),
            settings(&[("environment.base", r#""https://vault.example.com""#)])
        );
    }

    #[test]
    fn flattens_every_branch_of_a_source_holding_more_than_one_namespace() {
        assert_eq!(
            flatten(
                r#"{
                    "environment": { "base": "https://vault.example.com", "api": "https://api.example.com" },
                    "generator": { "password": { "length": 20 } }
                }"#
            ),
            settings(&[
                ("environment.base", r#""https://vault.example.com""#),
                ("environment.api", r#""https://api.example.com""#),
                ("generator.password.length", "20"),
            ])
        );
    }

    #[test]
    fn treats_a_proto_key_as_an_ordinary_key() {
        assert_eq!(
            flatten(r#"{ "__proto__": { "polluted": true } }"#),
            settings(&[("__proto__.polluted", "true")])
        );
    }

    #[test]
    fn encodes_numbers_the_way_javascript_prints_them() {
        let cases = [
            ("1.0", "1"),
            ("1.5", "1.5"),
            ("-0", "0"),
            ("-0.0", "0"),
            ("1e2", "100"),
            ("0.1", "0.1"),
            ("1e21", "1e+21"),
            ("1.5e-8", "1.5e-8"),
            ("1e-7", "1e-7"),
            ("0.000001", "0.000001"),
            ("123456789012345680000", "123456789012345680000"),
            ("9007199254740991", "9007199254740991"),
            ("12345678901234567890", "12345678901234567000"),
            ("-12345678901234567890", "-12345678901234567000"),
        ];

        for (input, expected) in cases {
            assert_eq!(
                flatten(&format!(r#"{{ "value": {input} }}"#)),
                settings(&[("value", expected)]),
                "input {input}"
            );
        }
    }

    #[test]
    fn escapes_strings_the_way_javascript_does() {
        assert_eq!(
            flatten(r#"{ "value": "quote \" slash / tab \t control \u0001 unicode é" }"#),
            settings(&[(
                "value",
                r#""quote \" slash / tab \t control \u0001 unicode é""#
            )])
        );
    }

    #[test]
    fn encodes_objects_inside_an_array_leaf_with_array_index_keys_first() {
        assert_eq!(
            flatten(r#"{ "value": [{ "2": 1, "1": 2 }] }"#),
            settings(&[("value", r#"[{"1":2,"2":1}]"#)])
        );
    }

    #[test]
    fn keeps_the_last_value_of_a_duplicated_key() {
        assert_eq!(
            flatten(r#"{ "value": 1, "value": 2 }"#),
            settings(&[("value", "2")])
        );
    }

    #[test]
    fn a_profile_carries_the_schema_version_and_a_timestamp_in_seconds() {
        let before = now_seconds();
        let profile = profile_from_json(r#"{ "environment": { "base": "https://a" } }"#)
            .expect("an object is accepted");
        let after = now_seconds();

        assert_eq!(profile.version, MANAGEMENT_PROFILE_VERSION);
        assert!((before..=after).contains(&profile.updated_at));
        assert_eq!(
            profile.settings,
            settings(&[("environment.base", r#""https://a""#)])
        );
    }

    #[test]
    fn rejects_input_that_is_not_json() {
        let error = profile_from_json("{ not json").expect_err("invalid JSON is rejected");

        assert!(matches!(error, ManagedSettingsError::InvalidJson(_)));
    }

    #[test]
    fn rejects_a_top_level_value_that_is_not_an_object() {
        for (input, found) in [
            ("[]", "an array"),
            ("\"text\"", "a string"),
            ("1", "a number"),
            ("true", "a boolean"),
            ("null", "null"),
        ] {
            let error = profile_from_json(input).expect_err("a non-object is rejected");

            assert!(
                matches!(&error, ManagedSettingsError::NotAnObject(name) if name == found),
                "input {input} gave {error:?}"
            );
        }
    }
}
