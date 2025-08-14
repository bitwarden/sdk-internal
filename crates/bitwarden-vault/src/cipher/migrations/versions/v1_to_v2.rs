use bitwarden_core::key_management::{KeyIds, SymmetricKeyId};
use bitwarden_crypto::KeyStoreContext;

use crate::migrations::registry::Migration;

pub struct V1ToV2Migration;

impl Migration for V1ToV2Migration {
    fn from_version(&self) -> u32 {
        1
    }

    fn to_version(&self) -> u32 {
        2
    }

    fn migrate(
        &self,
        cipher_data: &mut serde_json::Value,
        _ctx: Option<&mut KeyStoreContext<KeyIds>>,
        _cipher_key: Option<SymmetricKeyId>,
    ) -> Result<(), crate::CipherError> {
        if let Some(obj) = cipher_data.as_object_mut() {
            if !obj.contains_key("SecurityQuestions") {
                obj.insert(
                    "SecurityQuestions".to_string(),
                    serde_json::Value::Array(vec![]),
                );
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v1_to_v2_adds_security_questions() {
        let mut data = serde_json::json!({
            "Username": "2.PE7g9afvjh9N57ORdUlCDQ==|d8C4kLo0CYAKfa9Gjp4mqg==|YmgGDxGWXtIzW+TJsjDW3CoS0k+U4NZSAwygzq6zV/0=",
            "Password": "2.sGpXvg4a6BPFOPN3ePxZaQ==|ChseXEroqhbB11sBk+hH4Q==|SVz2WMGDvZSJwTivSnCFCCfQmmnuiHHPEgw4gzr09pQ=",
            "Uris": [],
            "Totp": null
        });

        V1ToV2Migration.migrate(&mut data, None, None).unwrap();

        assert!(data.get("SecurityQuestions").is_some());
        assert_eq!(data["SecurityQuestions"], serde_json::json!([]));
    }
}
