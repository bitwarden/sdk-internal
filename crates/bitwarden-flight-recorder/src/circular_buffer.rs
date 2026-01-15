//! Thread-safe circular buffer implementation.

use std::{
    collections::VecDeque,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

/// Internal wrapper that stores items with their size for accurate eviction tracking.
struct SizedItem<T> {
    item: T,
    size: usize,
}

/// A thread-safe circular buffer with FIFO eviction.
///
/// When the buffer reaches its capacity, the oldest items are automatically
/// removed to make room for new ones.
pub struct CircularBuffer<T> {
    buffer: Mutex<VecDeque<SizedItem<T>>>,
    capacity: usize,
    #[allow(dead_code)]
    max_size_bytes: usize,
    current_size_bytes: AtomicUsize,
}

impl<T> std::fmt::Debug for CircularBuffer<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CircularBuffer")
            .field("capacity", &self.capacity)
            .field("max_size_bytes", &self.max_size_bytes)
            .field("current_size_bytes", &self.current_size_bytes.load(Ordering::Relaxed))
            .finish()
    }
}

impl<T: Clone> CircularBuffer<T> {
    /// Create a new circular buffer with the given capacity and size limit.
    pub fn new(capacity: usize, max_size_bytes: usize) -> Self {
        Self {
            buffer: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
            max_size_bytes,
            current_size_bytes: AtomicUsize::new(0),
        }
    }

    /// Push an item into the buffer with its size.
    ///
    /// If the buffer is at capacity, the oldest item is evicted and returned.
    /// The size is used to track total buffer memory usage.
    pub fn push(&self, item: T, item_size: usize) -> Option<T> {
        let mut buffer = self.buffer.lock().expect("CircularBuffer mutex poisoned");

        // Evict oldest if at capacity - subtract the EVICTED item's size
        let evicted = if buffer.len() >= self.capacity {
            if let Some(old) = buffer.pop_front() {
                self.current_size_bytes.fetch_sub(old.size, Ordering::Relaxed);
                Some(old.item)
            } else {
                None
            }
        } else {
            None
        };

        // Push new item with its size
        buffer.push_back(SizedItem { item, size: item_size });
        self.current_size_bytes.fetch_add(item_size, Ordering::Relaxed);

        evicted
    }

    /// Drain all items from the buffer.
    ///
    /// This empties the buffer and returns all items in order (oldest first).
    /// The size tracking is reset to zero.
    pub fn drain(&self) -> Vec<T> {
        let mut buffer = self.buffer.lock().expect("CircularBuffer mutex poisoned");
        let items: Vec<T> = buffer.drain(..).map(|sized| sized.item).collect();
        self.current_size_bytes.store(0, Ordering::Relaxed);
        items
    }

    /// Get the current number of items in the buffer.
    pub fn len(&self) -> usize {
        self.buffer.lock().expect("CircularBuffer mutex poisoned").len()
    }

    /// Get the current total size of items in bytes.
    pub fn size_bytes(&self) -> usize {
        self.current_size_bytes.load(Ordering::Relaxed)
    }

    /// Check if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.lock().expect("CircularBuffer mutex poisoned").is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circular_buffer_fifo_eviction() {
        let buffer = CircularBuffer::new(3, 1000);

        buffer.push("event1".to_string(), 100);
        buffer.push("event2".to_string(), 100);
        buffer.push("event3".to_string(), 100);

        // Fourth push should evict first
        let evicted = buffer.push("event4".to_string(), 100);
        assert_eq!(evicted, Some("event1".to_string()));

        let contents = buffer.drain();
        assert_eq!(contents, vec!["event2", "event3", "event4"]);
    }

    #[test]
    fn test_circular_buffer_size_tracking() {
        let buffer = CircularBuffer::new(100, 1000);

        buffer.push("small".to_string(), 50);
        assert_eq!(buffer.size_bytes(), 50);

        buffer.push("large".to_string(), 500);
        assert_eq!(buffer.size_bytes(), 550);

        buffer.drain();
        assert_eq!(buffer.size_bytes(), 0);
    }

    #[test]
    fn test_eviction_updates_size() {
        let buffer = CircularBuffer::new(2, 1000);

        buffer.push("a".to_string(), 100);
        buffer.push("b".to_string(), 200);
        assert_eq!(buffer.size_bytes(), 300);

        buffer.push("c".to_string(), 50); // Evicts "a" (100 bytes)
        assert_eq!(buffer.size_bytes(), 250); // 200 + 50
    }

    #[test]
    fn test_len_and_is_empty() {
        let buffer = CircularBuffer::new(10, 1000);

        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);

        buffer.push("item".to_string(), 10);
        assert!(!buffer.is_empty());
        assert_eq!(buffer.len(), 1);

        buffer.drain();
        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);
    }

    #[test]
    fn test_drain_returns_items_in_order() {
        let buffer = CircularBuffer::new(5, 1000);

        buffer.push("first".to_string(), 10);
        buffer.push("second".to_string(), 10);
        buffer.push("third".to_string(), 10);

        let items = buffer.drain();
        assert_eq!(items, vec!["first", "second", "third"]);
    }
}
