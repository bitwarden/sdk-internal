use std::{path::Path, sync::Arc};

use bitwarden_send::{Send, SendClientExt, SendListView, SendView};

use crate::{error::Error, Client, Result};

#[derive(uniffi::Object)]
pub struct SendClient(pub Arc<Client>);

#[uniffi::export]
impl SendClient {
    /// Encrypt send
    pub fn encrypt(&self, send: SendView) -> Result<Send> {
        Ok(self
            .0
             .0
            .sends()
            .encrypt(send)
            .map_err(Error::SendEncrypt)?)
    }

    /// Encrypt a send file in memory
    pub fn encrypt_buffer(&self, send: Send, buffer: Vec<u8>) -> Result<Vec<u8>> {
        Ok(self
            .0
             .0
            .sends()
            .encrypt_buffer(send, &buffer)
            .map_err(Error::SendEncrypt)?)
    }

    /// Encrypt a send file located in the file system
    pub fn encrypt_file(
        &self,
        send: Send,
        decrypted_file_path: String,
        encrypted_file_path: String,
    ) -> Result<()> {
        Ok(self
            .0
             .0
            .sends()
            .encrypt_file(
                send,
                Path::new(&decrypted_file_path),
                Path::new(&encrypted_file_path),
            )
            .map_err(Error::SendEncryptFile)?)
    }

    /// Decrypt send
    pub fn decrypt(&self, send: Send) -> Result<SendView> {
        Ok(self
            .0
             .0
            .sends()
            .decrypt(send)
            .map_err(Error::SendDecrypt)?)
    }

    /// Decrypt send list
    pub fn decrypt_list(&self, sends: Vec<Send>) -> Result<Vec<SendListView>> {
        Ok(self
            .0
             .0
            .sends()
            .decrypt_list(sends)
            .map_err(Error::SendDecrypt)?)
    }

    /// Decrypt a send file in memory
    pub fn decrypt_buffer(&self, send: Send, buffer: Vec<u8>) -> Result<Vec<u8>> {
        Ok(self
            .0
             .0
            .sends()
            .decrypt_buffer(send, &buffer)
            .map_err(Error::SendDecrypt)?)
    }

    /// Decrypt a send file located in the file system
    pub fn decrypt_file(
        &self,
        send: Send,
        encrypted_file_path: String,
        decrypted_file_path: String,
    ) -> Result<()> {
        Ok(self
            .0
             .0
            .sends()
            .decrypt_file(
                send,
                Path::new(&encrypted_file_path),
                Path::new(&decrypted_file_path),
            )
            .map_err(Error::SendDecryptFile)?)
    }
}
