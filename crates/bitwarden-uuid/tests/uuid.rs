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
