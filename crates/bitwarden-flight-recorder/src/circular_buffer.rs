//! Thread-safe circular buffer implementation.

use std::{collections::VecDeque, sync::Mutex};

// Static assertion: CircularBuffer<T> must be Send + Sync for any Send type T.
// This is required because the buffer is stored in a global OnceLock and accessed
// from multiple threads. This assertion documents the requirement and will cause
// a compile error if future changes break thread safety.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    // String is a common Send type, so we use it as the test type
    assert_send_sync::<CircularBuffer<String>>();
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

impl<T: Clone> CircularBuffer<T> {
    /// Create a new circular buffer with the given capacity.
    pub fn new(capacity: usize) -> Self {
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

        // Evict oldest if at capacity
        let evicted = if buffer.len() >= self.capacity {
            buffer.pop_front()
        } else {
            None
        };

        buffer.push_back(item);
        evicted
    }

    /// Drain all items from the buffer.
    ///
    /// This empties the buffer and returns all items in order (oldest first).
    #[must_use]
    pub fn drain(&self) -> Vec<T> {
        let mut buffer = self.buffer.lock().expect("CircularBuffer mutex poisoned");
        buffer.drain(..).collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circular_buffer_fifo_eviction() {
        let buffer = CircularBuffer::new(3);

        buffer.push("event1".to_string());
        buffer.push("event2".to_string());
        buffer.push("event3".to_string());

        // Fourth push should evict first
        let evicted = buffer.push("event4".to_string());
        assert_eq!(evicted, Some("event1".to_string()));

        let contents = buffer.drain();
        assert_eq!(contents, vec!["event2", "event3", "event4"]);
    }

    #[test]
    fn test_len_and_is_empty() {
        let buffer = CircularBuffer::new(10);

        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);

        buffer.push("item".to_string());
        assert!(!buffer.is_empty());
        assert_eq!(buffer.len(), 1);

        let _ = buffer.drain();
        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);
    }

    #[test]
    fn test_drain_returns_items_in_order() {
        let buffer = CircularBuffer::new(5);

        buffer.push("first".to_string());
        buffer.push("second".to_string());
        buffer.push("third".to_string());

        let items = buffer.drain();
        assert_eq!(items, vec!["first", "second", "third"]);
    }
}
