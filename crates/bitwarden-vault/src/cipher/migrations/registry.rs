use bitwarden_core::key_management::{KeyIds, SymmetricKeyId};
use bitwarden_crypto::KeyStoreContext;

use crate::{
    migrations::versions::{V1ToV2Migration, V2ToV3Migration},
    CipherError,
};

pub trait Migration {
    fn source_version(&self) -> u32;
    fn target_version(&self) -> u32;
    fn migrate(
        &self,
        cipher_data: &mut serde_json::Value,
        ctx: Option<&mut KeyStoreContext<KeyIds>>,
        cipher_key: Option<SymmetricKeyId>,
    ) -> Result<(), CipherError>; // this can be migration error
}

pub struct MigrationRegistry {
    migrations: Vec<Box<dyn Migration>>,
}

impl MigrationRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            migrations: Vec::new(),
        };

        // something like this
        registry.register(Box::new(V1ToV2Migration));
        registry.register(Box::new(V2ToV3Migration));

        registry
    }

    pub fn register(&mut self, migration: Box<dyn Migration>) {
        self.migrations.push(migration);
    }

    pub fn migrate(
        &self,
        cipher_data: &mut serde_json::Value,
        source_version: u32,
        target_version: u32,
        mut ctx: Option<&mut KeyStoreContext<KeyIds>>,
        cipher_key: Option<SymmetricKeyId>,
    ) -> Result<(), CipherError> {
        let mut current_version = source_version;

        while current_version < target_version {
            let migration = self
                .migrations
                .iter()
                .find(|m| m.source_version() == current_version)
                .ok_or(CipherError::UnsupportedCipherVersion(current_version))?;

            migration.migrate(cipher_data, ctx.as_deref_mut(), cipher_key)?;
            current_version = migration.target_version();
        }

        Ok(())
    }
}
