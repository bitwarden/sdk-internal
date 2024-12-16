use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub enum AEAD_Type {
    // 0
    JSON_ENCSTRING,
}

impl AEAD_Type {
    fn from_u8(i: u8) -> Result<AEAD_Type, String> {
        match i {
            0 => Ok(AEAD_Type::JSON_ENCSTRING),
            _ => Err(format!("Invalid value for AEAD_Type: {}", i)),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct AdditionalData {
    inner: HashMap<String, String>,
}

impl AdditionalData {
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    pub fn insert(&mut self, key: String, value: String) {
        self.inner.insert(key, value);
    }

    pub fn get(&self, key: &str) -> Option<&String> {
        self.inner.get(key)
    }
}

pub fn encode_aead(aead: &AEAD_Type, aead_map: &AdditionalData) -> Result<Vec<u8>, String> {
    // serde
    match aead {
        AEAD_Type::JSON_ENCSTRING => {
            let json = serde_json::to_string(aead_map).unwrap();
            let json_bytes = json.as_bytes();
            let json_len = json_bytes.len();
            let mut buf = Vec::with_capacity(json_len + 1);
            buf.push(0);
            buf.extend_from_slice(json_bytes);
            Ok(buf)
        }
    }
}

pub fn decode_aead(buf: &[u8]) -> Result<AdditionalData, String> {
    let aead = AEAD_Type::from_u8(buf[0])?;
    match aead {
        AEAD_Type::JSON_ENCSTRING => {
            let json = std::str::from_utf8(&buf[1..]).unwrap();
            let aead_map: AdditionalData = serde_json::from_str(json).unwrap();
            Ok(aead_map)
        }
    }
}
