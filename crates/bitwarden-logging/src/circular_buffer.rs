//! Thread-safe circular buffer implementation.

use std::{collections::VecDeque, num::NonZeroUsize, sync::Mutex};

// Static assertion: CircularBuffer<T> must be Send + Sync for any Send type T.
// This is required because the buffer is shared across threads via Arc.
// T only needs Send (not Sync) because Mutex<VecDeque<T>> provides the Sync guarantee.
const _: () = {
    fn _assert_send_sync<T: Send + Sync>() {}
    fn _assert_circular_buffer<T: Send>() {
        _assert_send_sync::<CircularBuffer<T>>();
    }
};

/// A thread-safe circular buffer with FIFO eviction.
///
/// When the buffer reaches its capacity, the oldest items are automatically
/// removed to make room for new ones.
pub struct CircularBuffer<T> {
    buffer: Mutex<VecDeque<T>>,
    capacity: usize,
}

impl<T> std::fmt::Debug for CircularBuffer<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CircularBuffer")
            .field("capacity", &self.capacity)
            .finish()
    }
}

impl<T> CircularBuffer<T> {
    /// Create a new circular buffer with the given capacity.
    pub fn new(capacity: NonZeroUsize) -> Self {
        let capacity = capacity.get();
        Self {
            buffer: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
        }
    }

    /// Push an item into the buffer.
    ///
    /// If the buffer is at capacity, the oldest item is evicted and returned.
    pub fn push(&self, item: T) -> Option<T> {
        let mut buffer = self.buffer.lock().expect("CircularBuffer mutex poisoned");

        let evicted = if buffer.len() >= self.capacity {
            buffer.pop_front()
        } else {
            None
        };

        buffer.push_back(item);
        evicted
    }

    /// Get the current number of items in the buffer.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.buffer
            .lock()
            .expect("CircularBuffer mutex poisoned")
            .len()
    }

    /// Check if the buffer is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buffer
            .lock()
            .expect("CircularBuffer mutex poisoned")
            .is_empty()
    }
}

impl<T: Clone> CircularBuffer<T> {
    /// Read all items from the buffer.
    ///
    /// Returns a snapshot of current buffer contents in order (oldest first).
    #[must_use]
    pub fn read(&self) -> Vec<T> {
        let mut result = Vec::with_capacity(self.capacity);
        let buffer = self.buffer.lock().expect("CircularBuffer mutex poisoned");
        result.extend(buffer.iter().cloned());
        result
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn test_push_and_read() {
        let buffer = CircularBuffer::new(NonZeroUsize::new(5).unwrap());
        buffer.push("first".to_string());
        buffer.push("second".to_string());
        buffer.push("third".to_string());

        let items = buffer.read();
        assert_eq!(items, vec!["first", "second", "third"]);
    }

    #[test]
    fn test_fifo_eviction() {
        let buffer = CircularBuffer::new(NonZeroUsize::new(3).unwrap());
        buffer.push("event1".to_string());
        buffer.push("event2".to_string());
        buffer.push("event3".to_string());

        // Fourth push should evict the oldest
        let evicted = buffer.push("event4".to_string());
        assert_eq!(evicted, Some("event1".to_string()));

        let contents = buffer.read();
        assert_eq!(contents, vec!["event2", "event3", "event4"]);
    }

    #[test]
    fn test_len_and_is_empty() {
        let buffer = CircularBuffer::new(NonZeroUsize::new(10).unwrap());
        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);

        buffer.push("item".to_string());
        assert!(!buffer.is_empty());
        assert_eq!(buffer.len(), 1);

        let items = buffer.read();
        assert_eq!(items.len(), 1);
    }

    #[test]
    fn test_read_preserves_contents() {
        let buffer = CircularBuffer::new(NonZeroUsize::new(5).unwrap());
        buffer.push("a".to_string());
        buffer.push("b".to_string());

        let first_read = buffer.read();
        let second_read = buffer.read();
        assert_eq!(first_read, second_read);
    }

    #[test]
    fn test_concurrent_push() {
        let buffer = Arc::new(CircularBuffer::new(NonZeroUsize::new(1000).unwrap()));
        let handles: Vec<_> = (0..10)
            .map(|i| {
                let buf = Arc::clone(&buffer);
                std::thread::spawn(move || {
                    for j in 0..100 {
                        buf.push(format!("thread{i}-event{j}"));
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread panicked");
        }

        assert_eq!(buffer.len(), 1000);
    }
}
