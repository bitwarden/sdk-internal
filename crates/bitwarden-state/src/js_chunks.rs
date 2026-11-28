//! [`JsChunks`], for repositories that receive their items as JavaScript values.

use std::{cell::RefCell, future::Future, marker::PhantomData};

use bitwarden_threading::ThreadBoundRunner;
use futures::StreamExt;
use js_sys::{
    Array,
    wasm_bindgen::{JsCast, JsValue},
};
use serde::de::DeserializeOwned;

use crate::repository::{RepositoryError, RepositoryStream};

/// JavaScript values of a list, kept on the JavaScript thread and converted to `V` a chunk at a
/// time.
///
/// A JavaScript value is a handle into the JavaScript heap, so holding every item as a value costs
/// four bytes of WASM memory each, and only the chunk being converted is held as `V`. Create it on
/// the JavaScript thread, for example inside [`ThreadBoundRunner::run_in_thread`]; it can then be
/// sent anywhere.
pub struct JsChunks<V> {
    values: ThreadBoundRunner<RefCell<std::vec::IntoIter<JsValue>>>,
    item: PhantomData<fn() -> V>,
}

impl<V: DeserializeOwned + Send + Sync + 'static> JsChunks<V> {
    /// Takes the items of `array`, which has to be a JavaScript array.
    pub fn from_array(array: JsValue) -> Result<Self, RepositoryError> {
        let array: Array = array
            .dyn_into()
            .map_err(|_| RepositoryError::Internal("Expected an array of items".to_owned()))?;
        Ok(Self::new(array.to_vec()))
    }

    /// Takes `values`, one per item.
    pub fn new(values: Vec<JsValue>) -> Self {
        Self {
            values: ThreadBoundRunner::new(RefCell::new(values.into_iter())),
            item: PhantomData,
        }
    }

    /// The items in chunks of up to `chunk_size` (at least one), in order. A value that does not
    /// convert to `V` yields an `Err` and ends the stream.
    pub fn into_stream(self, chunk_size: usize) -> RepositoryStream<V> {
        let chunk_size = chunk_size.max(1);
        futures::stream::unfold(Some(self.values), move |values| async move {
            let values = values?;
            let chunk = values
                .run_in_thread(move |values| async move { next_chunk::<V>(&values, chunk_size) })
                .await
                .map_err(|error| RepositoryError::Internal(error.to_string()))
                .and_then(|chunk| chunk);
            match chunk {
                Ok(chunk) if chunk.is_empty() => None,
                Ok(chunk) => Some((Ok(chunk), Some(values))),
                Err(error) => Some((Err(error), None)),
            }
        })
        .boxed()
    }

    /// The stream of the `JsChunks` that `start` resolves to, starting it when first polled. An
    /// `Err` from `start` is the stream's only item.
    pub fn stream_after(
        start: impl Future<Output = Result<Self, RepositoryError>> + Send + 'static,
        chunk_size: usize,
    ) -> RepositoryStream<V> {
        futures::stream::once(start)
            .flat_map(move |chunks| match chunks {
                Ok(chunks) => chunks.into_stream(chunk_size),
                Err(error) => futures::stream::iter([Err(error)]).boxed(),
            })
            .boxed()
    }
}

/// Converts the next `chunk_size` values, releasing each handle as it goes.
fn next_chunk<V: DeserializeOwned>(
    values: &RefCell<std::vec::IntoIter<JsValue>>,
    chunk_size: usize,
) -> Result<Vec<V>, RepositoryError> {
    let mut values = values.borrow_mut();
    let mut chunk = Vec::with_capacity(chunk_size.min(values.len()));
    for value in values.by_ref().take(chunk_size) {
        chunk.push(
            tsify::serde_wasm_bindgen::from_value(value)
                .map_err(|error| RepositoryError::Internal(error.to_string()))?,
        );
    }
    Ok(chunk)
}
