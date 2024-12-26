use serde::{Deserialize, Serialize};

use super::fingerprint::Fingerprint;

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct StagedKey<T> {
    active_key: T,
    staged_key: Option<T>,
}

impl<T> StagedKey<T> {
    pub(super) fn new(key: T) -> Self {
        StagedKey {
            active_key: key,
            staged_key: None,
        }
    }

    fn stage_key(&mut self, key: T) {
        self.staged_key = Some(key);
    }

    fn get_staged_key(&self) -> &Option<T> {
        &self.staged_key
    }

    fn finalize_key(&mut self) {
        self.active_key = self.staged_key.take().unwrap();
        self.staged_key = None;
    }
}

impl<T> StagedKey<T>
where
    T: Fingerprint,
{
    fn fingerprint(&self) -> [u8; 32] {
        self.active_key.fingerprint()
    }
}
