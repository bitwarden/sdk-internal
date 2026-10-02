#![allow(missing_docs)]

use bitwarden_ffi::wasm_record;
use serde::{Deserialize, Serialize};

// --- Test: a serde DTO keeps its serde and tsify attributes ---

#[wasm_record]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Point {
    pub x: i32,
    #[cfg_attr(feature = "wasm", tsify(optional))]
    pub label: Option<String>,
}

#[test]
fn a_record_serializes_under_its_serde_attributes() {
    let json = serde_json::to_string(&Point {
        x: 1,
        label: Some("origin".to_owned()),
    })
    .unwrap();

    assert_eq!(json, r#"{"x":1,"label":"origin"}"#);
    assert_eq!(serde_json::from_str::<Point>(&json).unwrap().x, 1);
}

// --- Test: enums are records too ---

#[wasm_record]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Kind {
    ItemOne,
    ItemTwo,
}

#[test]
fn an_enum_record_serializes_under_its_serde_attributes() {
    assert_eq!(
        serde_json::to_string(&Kind::ItemOne).unwrap(),
        r#""itemOne""#
    );
}
