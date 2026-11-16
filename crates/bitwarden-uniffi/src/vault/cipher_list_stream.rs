//! Ciphers listed and decrypted lazily, a chunk per call from Swift or Kotlin.

use bitwarden_vault::{Cipher, CipherListView, DecryptStreamError, DecryptedChunk};
use futures::{Stream, StreamExt, lock::Mutex, stream::BoxStream};

use crate::Result;

/// A cipher out of a [`CipherListStream`].
#[allow(clippy::large_enum_variant)]
#[derive(uniffi::Enum)]
pub enum CipherListItem {
    /// The cipher decrypted to its list view.
    Decrypted { view: CipherListView },
    /// The cipher failed to decrypt, and is returned as it is stored.
    Failed { cipher: Cipher },
}

impl From<Result<CipherListView, Box<Cipher>>> for CipherListItem {
    fn from(result: Result<CipherListView, Box<Cipher>>) -> Self {
        match result {
            Ok(view) => Self::Decrypted { view },
            Err(cipher) => Self::Failed { cipher: *cipher },
        }
    }
}

/// The ciphers in state, read and decrypted a chunk at a time as [`Self::next_chunk`] is called.
///
/// Memory holds one chunk at a time when the cipher repository reads lazily, for example a
/// client-managed repository whose `list_iter` iterator reads each batch only when asked for it.
#[derive(uniffi::Object)]
pub struct CipherListStream(
    Mutex<Option<BoxStream<'static, Result<DecryptedChunk, DecryptStreamError>>>>,
);

impl CipherListStream {
    pub(crate) fn new(
        chunks: impl Stream<Item = Result<DecryptedChunk, DecryptStreamError>> + Send + 'static,
    ) -> Self {
        Self(Mutex::new(Some(chunks.boxed())))
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl CipherListStream {
    /// Reads and decrypts the next chunk of ciphers, in the repository's order, or returns `None`
    /// when there are no more ciphers.
    ///
    /// A cipher that fails to decrypt is a [`CipherListItem::Failed`] in its place. A failure of
    /// the listing itself is returned once as an error, and ends the stream: the repository failing
    /// to read, or the vault being locked when a chunk is decrypted. Every call after the end
    /// returns `None`.
    pub async fn next_chunk(&self) -> Result<Option<Vec<CipherListItem>>> {
        let mut chunks = self.0.lock().await;
        let Some(stream) = chunks.as_mut() else {
            return Ok(None);
        };
        match stream.next().await {
            Some(Ok(chunk)) => Ok(Some(chunk.into_iter().map(Into::into).collect())),
            Some(Err(error)) => {
                *chunks = None;
                Err(error.into())
            }
            None => {
                *chunks = None;
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_state::repository::RepositoryError;

    use super::*;
    use crate::error::BitwardenError;

    #[tokio::test]
    async fn returns_each_chunk_then_none() {
        let stream = CipherListStream::new(futures::stream::iter([Ok(Vec::new()), Ok(Vec::new())]));

        assert_eq!(stream.next_chunk().await.unwrap().map(|c| c.len()), Some(0));
        assert_eq!(stream.next_chunk().await.unwrap().map(|c| c.len()), Some(0));
        assert!(stream.next_chunk().await.unwrap().is_none());
        assert!(stream.next_chunk().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn ends_after_the_first_error() {
        let stream = CipherListStream::new(futures::stream::iter([
            Ok(Vec::new()),
            Err(DecryptStreamError::VaultLocked),
            Ok(Vec::new()),
            Err(DecryptStreamError::Repository(RepositoryError::Internal(
                "unavailable".to_owned(),
            ))),
        ]));

        assert!(stream.next_chunk().await.unwrap().is_some());
        assert!(matches!(
            stream.next_chunk().await,
            Err(BitwardenError::DecryptStream(
                DecryptStreamError::VaultLocked
            ))
        ));
        assert!(stream.next_chunk().await.unwrap().is_none());
        assert!(stream.next_chunk().await.unwrap().is_none());
    }
}
