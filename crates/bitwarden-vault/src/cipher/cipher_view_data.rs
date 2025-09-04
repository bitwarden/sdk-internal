use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tsify::Tsify;

use crate::{
    CardView, FieldView, IdentityView, LoginView, PasswordHistoryView, SecureNoteView, SshKeyView,
};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
// #[serde(tag="version")]
#[serde(untagged)]
pub enum CipherVersionData {
    // #[serde (rename = "1")] // TODO: NEed to see if we can 'trick' serde into using a number instead of a string here... else may need to manually impl Serialize/Deserialize.
    V1(CipherVersionDataV1),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(untagged)]
pub enum CipherType2 {
    Card(CardView),
    Identity(IdentityView),
    Login(LoginView),
    SshKey(SshKeyView),
    SecureNote(SecureNoteView),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct CipherVersionDataV1 {
    pub notes: Option<String>,
    pub fields: Option<Vec<FieldView>>,
    pub password_history: Option<Vec<PasswordHistoryView>>,
    #[serde(flatten)]
    cipher_type: CipherType2,
}

impl CipherVersionData {
    fn version(&self) -> u64 {
        match self {
            Self::V1(..) => 1,
            // Self::V2(..) => 2,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct CipherViewData {
    #[serde(flatten)]
    data: CipherVersionData,

    #[serde(flatten)]
    // TODO: HashMap is not ideal here, but serde_json::Value is not supported by uniffi. This eats any non-string values, which is not ideal.
    other_data: HashMap<String, String>,
    // other_data: Map<String, Value>,
}

impl CipherViewData {
    pub fn version(&self) -> u64 {
        self.data.version()
    }
}

// #[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_v1() {
        let data = CipherVersionData::V1(CipherVersionDataV1 {
            notes: Some("Test notes".to_string()),
            fields: Some(vec![]),
            password_history: Some(vec![]),
            cipher_type: CipherType2::Login(LoginView {
                username: Some("testuser".to_string()),
                password: Some("testpassword".to_string()),
                password_revision_date: None,
                totp: None,
                autofill_on_page_load: None,
                fido2_credentials: None,
                uris: None,
            }),
        });
        let cipher_view_data = CipherViewData {
            data,
            other_data: HashMap::new(),
        };
        let serialized = serde_json::to_string_pretty(&cipher_view_data).unwrap();
        panic!("Serialized V1 CipherViewData:\n{}", serialized);
    }

    #[test]
    fn test_deserialize_v1() {
        let json_data = r#"
   [{
      "collectionIds": [],
      "folderId": null,
      "favorite": false,
      "edit": true,
      "viewPassword": true,
      "permissions": {
        "delete": true,
        "restore": true
      },
      "id": "8493cbbb-0733-4204-a255-b3460163a3bf",
      "organizationId": null,
      "type": 1,
      "data": {
        "uri": null,
        "uris": [],
        "username": "2.uXRs3AGTuyJc7DhIDjw1ig==|A8wYld5QW+TxBEDM/lvWdA==|/zcjqwTtPnbQ1Pyr0r1Y5u3JSHUc2fE3c5OdDrVbBXc=",
        "password": "2.yZYriALW1LH2ZyDmflp9Gw==|768of9Lpycim/5lKWaMkU2bzo4ssmGrT8VMX1iFCEHc=|HxluYTFfIjTao28P1fMmmPYsHqdJbJtYC9M/0w0uy2g=",
        "passwordRevisionDate": null,
        "totp": null,
        "autofillOnPageLoad": null,
        "fido2Credentials": null,
        "name": "2.Dn+st9iSn0kFxljKRID3/w==|2xMM54P5w36U7MbE7mjHapZNSzaXO/af/0YcbSQ5G1g=|WSIgMuapDCTRPTYnOlC+ai3b8JkVERLo2tMbVBeQybY=",
        "notes": null,
        "fields": null,
        "spasswordHistory": null
      },
      "name": "2.Dn+st9iSn0kFxljKRID3/w==|2xMM54P5w36U7MbE7mjHapZNSzaXO/af/0YcbSQ5G1g=|WSIgMuapDCTRPTYnOlC+ai3b8JkVERLo2tMbVBeQybY=",
      "notes": null,
      "login": {
        "uri": null,
        "uris": [],
        "username": "2.uXRs3AGTuyJc7DhIDjw1ig==|A8wYld5QW+TxBEDM/lvWdA==|/zcjqwTtPnbQ1Pyr0r1Y5u3JSHUc2fE3c5OdDrVbBXc=",
        "password": "2.yZYriALW1LH2ZyDmflp9Gw==|768of9Lpycim/5lKWaMkU2bzo4ssmGrT8VMX1iFCEHc=|HxluYTFfIjTao28P1fMmmPYsHqdJbJtYC9M/0w0uy2g=",
        "passwordRevisionDate": null,
        "totp": null,
        "autofillOnPageLoad": null,
        "fido2Credentials": null
      },
      "card": null,
      "identity": null,
      "secureNote": null,
      "sshKey": null,
      "fields": null,
      "passwordHistory": null,
      "attachments": null,
      "organizationUseTotp": false,
      "revisionDate": "2025-08-27T21:34:50.6466667Z",
      "creationDate": "2025-08-27T21:34:50.6466667Z",
      "deletedDate": null,
      "reprompt": 0,
      "key": null,
      "object": "cipherDetails"
    },
    {
      "collectionIds": [],
      "folderId": null,
      "favorite": false,
      "edit": true,
      "viewPassword": true,
      "permissions": {
        "delete": true,
        "restore": true
      },
      "id": "daa0dc8d-db9a-42d1-8bbf-b34c01674eab",
      "organizationId": null,
      "type": 3,
      "data": {
        "cardholderName": "2.B4uLbx7Qz14626+eUJ3k6Q==|4K6N+CaxLMnf835UqybDhA==|xusTaCbhCDac2Of225y0gZa82I0NwgSBtcv+muW3SaA=",
        "brand": "2.mktbmtt6oVagqJr0muwN5g==|69X6bEmK2CiHLvHgczch3A==|9R5fqATlNOBC0ACoFYSakLb75PGcGYGYnFbzhgEA1CQ=",
        "number": "2./Eyc03GMo8hmep1oJDwgnA==|pp9jDBhwXR51AYALwAhdU7VAi0vPO3iGWyQiqeVnHvY=|kSTLNyyuAnQ/J9B8ALpjcYFzHbjJestwEo3uGeWRjIo=",
        "expMonth": null,
        "expYear": "2.zKJpqVJPAVgTPSrEgqwROw==|hcl51LLAvWDJrGw6GtysDw==|BkK5xeFwEuoUHbhxDqWTFOJECF72g8shWK/yc1cI1Rw=",
        "code": "2.KSfMIb4pVP49QRlgwgC8Mw==|MKO0IgYWHbuQnkJ50KiIbA==|3KzcmCa6iCV/O4qOXj/UUkHJ19c8B98PURhxO09wmG4=",
        "name": "2.jDuSIctV+Kk4rYOjPm3Ztw==|zF/faVnmnGw+mEA1C8y1BQ==|EluIJySKhuz4fXPAmjfBuA0jcqjRBwD19CkusCG2Jsc=",
        "notes": null,
        "fields": null,
        "passwordHistory": null
      },
      "name": "2.jDuSIctV+Kk4rYOjPm3Ztw==|zF/faVnmnGw+mEA1C8y1BQ==|EluIJySKhuz4fXPAmjfBuA0jcqjRBwD19CkusCG2Jsc=",
      "notes": null,
      "login": null,
      "card": {
        "cardholderName": "2.B4uLbx7Qz14626+eUJ3k6Q==|4K6N+CaxLMnf835UqybDhA==|xusTaCbhCDac2Of225y0gZa82I0NwgSBtcv+muW3SaA=",
        "brand": "2.mktbmtt6oVagqJr0muwN5g==|69X6bEmK2CiHLvHgczch3A==|9R5fqATlNOBC0ACoFYSakLb75PGcGYGYnFbzhgEA1CQ=",
        "number": "2./Eyc03GMo8hmep1oJDwgnA==|pp9jDBhwXR51AYALwAhdU7VAi0vPO3iGWyQiqeVnHvY=|kSTLNyyuAnQ/J9B8ALpjcYFzHbjJestwEo3uGeWRjIo=",
        "expMonth": null,
        "expYear": "2.zKJpqVJPAVgTPSrEgqwROw==|hcl51LLAvWDJrGw6GtysDw==|BkK5xeFwEuoUHbhxDqWTFOJECF72g8shWK/yc1cI1Rw=",
        "code": "2.KSfMIb4pVP49QRlgwgC8Mw==|MKO0IgYWHbuQnkJ50KiIbA==|3KzcmCa6iCV/O4qOXj/UUkHJ19c8B98PURhxO09wmG4="
      },
      "identity": null,
      "secureNote": null,
      "sshKey": null,
      "fields": null,
      "passwordHistory": null,
      "attachments": null,
      "organizationUseTotp": false,
      "revisionDate": "2025-09-02T21:48:11.8633333Z",
      "creationDate": "2025-09-02T21:48:11.8633333Z",
      "deletedDate": null,
      "reprompt": 0,
      "key": null,
      "object": "cipherDetails"
    }
  ]
  "#;

        #[derive(Serialize, Deserialize, Debug)]
        pub struct Cipher {
            data: CipherVersionData,
        }

        let ciphers: Vec<Cipher> = serde_json::from_str(json_data).unwrap();
        for cipher in ciphers {
            let cipher = cipher.data;
            println!("Cipher version: {}", cipher.version());
            println!("Full cipher data: {:?}", cipher);
        }
    }
}
