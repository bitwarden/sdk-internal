#![allow(unexpected_cfgs)]

use bitwarden_uuid::uuid;

uuid!(TestId);

#[test]
fn test_parse_string() {
    use uuid::Uuid;

    let id: TestId = "12345678-1234-5678-1234-567812345678".parse().unwrap();
    let uuid: Uuid = id.into();

    assert_eq!(uuid.to_string(), "12345678-1234-5678-1234-567812345678");
}

#[test]
fn test_new() {
    use uuid::Uuid;

    let uuid = Uuid::new_v4();
    let id = TestId::new(uuid);

    assert_eq!(uuid, Into::<Uuid>::into(id));
}

#[test]
fn test_serialize() {
    let id: TestId = "d4a722ff-ce51-47f1-ba42-c2216f547851".parse().unwrap();

    let serialized = serde_json::to_string(&id).unwrap();

    assert_eq!(serialized, "\"d4a722ff-ce51-47f1-ba42-c2216f547851\"");
}

#[test]
fn test_deserialize() {
    let id: TestId = "d4a722ff-ce51-47f1-ba42-c2216f547851".parse().unwrap();

    let deserialized: TestId =
        serde_json::from_str("\"d4a722ff-ce51-47f1-ba42-c2216f547851\"").unwrap();

    assert_eq!(id, deserialized);
}

#[wasm_bindgen_test::wasm_bindgen_test]
#[allow(dead_code)]
fn test_wasm_serialize() {
    let id: TestId = "d4a722ff-ce51-47f1-ba42-c2216f547851"
        .parse()
        .expect("Test");

    let serialized = serde_wasm_bindgen::to_value(&id).expect("Test");

    assert_eq!(
        serialized.as_string().expect("Test"),
        "d4a722ff-ce51-47f1-ba42-c2216f547851"
    );
}
