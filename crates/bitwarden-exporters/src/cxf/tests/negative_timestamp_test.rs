//! Tests for handling negative timestamps in CXF import.
//!
//! Some credential managers (e.g., Google Password Manager) export timestamps
//! as the Windows FILETIME epoch (-11644473600) when no real date exists.

#[cfg(test)]
mod tests {
    use crate::cxf::import::{parse_cxf, sanitize_timestamps};

    #[test]
    fn test_sanitize_negative_creation_at() {
        let input = r#"{"id":"test","items":[{"id":"1","creationAt":-11644473600,"modifiedAt":1759783057,"title":"Test","credentials":[]}]}"#;
        let result = sanitize_timestamps(input);
        assert!(result.contains(r#""creationAt":null"#));
        assert!(result.contains(r#""modifiedAt":1759783057"#));
    }

    #[test]
    fn test_sanitize_negative_modified_at() {
        let input = r#"{"id":"test","items":[{"id":"1","creationAt":1759783057,"modifiedAt":-11644473600,"title":"Test","credentials":[]}]}"#;
        let result = sanitize_timestamps(input);
        assert!(result.contains(r#""creationAt":1759783057"#));
        assert!(result.contains(r#""modifiedAt":null"#));
    }

    #[test]
    fn test_sanitize_both_negative() {
        let input = r#"{"id":"test","items":[{"id":"1","creationAt":-11644473600,"modifiedAt":-11644473600,"title":"Test","credentials":[]}]}"#;
        let result = sanitize_timestamps(input);
        assert!(result.contains(r#""creationAt":null"#));
        assert!(result.contains(r#""modifiedAt":null"#));
    }

    #[test]
    fn test_sanitize_valid_timestamps_unchanged() {
        let input = r#"{"id":"test","items":[{"id":"1","creationAt":1759783057,"modifiedAt":1759783057,"title":"Test","credentials":[]}]}"#;
        let result = sanitize_timestamps(input);
        assert!(result.contains(r#""creationAt":1759783057"#));
        assert!(result.contains(r#""modifiedAt":1759783057"#));
    }

    #[test]
    fn test_sanitize_no_modification_returns_original() {
        let input = r#"{"id":"test","items":[{"id":"1","creationAt":1759783057,"modifiedAt":1759783057,"title":"Test","credentials":[]}]}"#;
        let result = sanitize_timestamps(input);
        // When no modification is needed, should return a borrowed reference to the original
        assert_eq!(result.as_ref(), input);
    }

    #[test]
    fn test_parse_cxf_with_negative_timestamps_does_not_error() {
        let input = r#"{
            "id": "DZSXp7iBQY-Fg-OofakQtQ",
            "username": "user@example.com",
            "email": "user@example.com",
            "fullName": "Test User",
            "collections": [],
            "items": [{
                "id": "9OF-QjVDQo2Wp2xWPw6ZhA",
                "creationAt": -11644473600,
                "modifiedAt": -11644473600,
                "title": "Test Entry",
                "credentials": [{
                    "type": "basic-auth",
                    "username": {
                        "id": "-eZX0Gw-TzOsBFwt67N7ZA",
                        "fieldType": "string",
                        "value": "testuser"
                    },
                    "password": {
                        "id": "wgu3wTcXSYawrGMWMtaANg",
                        "fieldType": "concealed-string",
                        "value": "testpass"
                    },
                    "urls": ["https://example.com"]
                }]
            }]
        }"#;
        let result = parse_cxf(input.to_string());
        assert!(result.is_ok(), "parse_cxf should not error on negative timestamps: {:?}", result.err());
    }
}
