#![allow(missing_docs)]

use std::pin::Pin;

pub struct BwIterator<T> {
    pub iter: Box<dyn Iterator<Item = T>>,
}

impl<T> BwIterator<T> {
    pub fn new(iter: impl Iterator<Item = T> + 'static) -> Self {
        Self {
            iter: Box::new(iter),
        }
    }
}

impl<T> IntoIterator for BwIterator<T> {
    type Item = T;
    type IntoIter = Box<dyn Iterator<Item = T>>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter
    }
}

pub struct BwStream<T> {
    pub stream: Pin<Box<dyn futures::stream::Stream<Item = T>>>,
}

impl<T> BwStream<T> {
    pub fn new(stream: impl futures::stream::Stream<Item = T> + 'static) -> Self {
        Self {
            stream: Box::pin(stream),
        }
    }
}
