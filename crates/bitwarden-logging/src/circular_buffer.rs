//! Thread-safe circular buffer implementation.

use std::{collections::VecDeque, num::NonZeroUsize, sync::Mutex};

// Static assertion: CircularBuffer<T> must be Send + Sync for any Send type T.
// This is required because the buffer is shared across threads via Arc.
// T only needs Send (not Sync) because the Mutex provides the Sync guarantee.
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
///
/// Each pushed item gets a sequence number, the count of items pushed before it, so readers can
/// resume after the last item they saw without duplicates. Evicted or taken items keep their
/// numbers, so later items continue the sequence.
pub struct CircularBuffer<T> {
    buffer: Mutex<Items<T>>,
    capacity: usize,
}

struct Items<T> {
    retained: VecDeque<T>,
    /// Number of items ever pushed.
    pushed: u64,
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
            buffer: Mutex::new(Items {
                retained: VecDeque::with_capacity(capacity),
                pushed: 0,
            }),
            capacity,
        }
    }

    /// Push an item into the buffer.
    ///
    /// If the buffer is at capacity, the oldest item is evicted and returned.
    pub fn push(&self, item: T) -> Option<T> {
        let mut buffer = self.buffer.lock().expect("CircularBuffer mutex poisoned");

        let evicted = if buffer.retained.len() >= self.capacity {
            buffer.retained.pop_front()
        } else {
            None
        };

        buffer.retained.push_back(item);
        buffer.pushed += 1;
        evicted
    }

    /// Get the current number of items in the buffer.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.buffer
            .lock()
            .expect("CircularBuffer mutex poisoned")
            .retained
            .len()
    }

    /// The maximum number of items the buffer holds.
    #[inline]
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Remove and return all items, oldest first. Their sequence numbers are not reused.
    #[must_use]
    pub fn take_all(&self) -> Vec<T> {
        self.buffer
            .lock()
            .expect("CircularBuffer mutex poisoned")
            .retained
            .drain(..)
            .collect()
    }

    /// Check if the buffer is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buffer
            .lock()
            .expect("CircularBuffer mutex poisoned")
            .retained
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
        result.extend(buffer.retained.iter().cloned());
        result
    }

    /// Read the retained items with a sequence number of at least `from`, oldest first, together
    /// with the sequence number of the first returned item. Items no longer retained are skipped.
    #[must_use]
    pub fn read_from(&self, from: u64) -> (u64, Vec<T>) {
        let buffer = self.buffer.lock().expect("CircularBuffer mutex poisoned");
        let oldest = buffer.pushed - buffer.retained.len() as u64;
        let first = from.clamp(oldest, buffer.pushed);
        let skip = usize::try_from(first - oldest).expect("offset is within the buffer length");
        (first, buffer.retained.iter().skip(skip).cloned().collect())
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
    fn test_read_from_resumes_by_sequence_number_across_eviction() {
        let buffer = CircularBuffer::new(NonZeroUsize::new(3).unwrap());
        for item in ["a", "b", "c"] {
            buffer.push(item);
        }
        assert_eq!(buffer.read_from(0), (0, vec!["a", "b", "c"]));
        assert_eq!(buffer.read_from(2), (2, vec!["c"]));

        // "a" and "b" are evicted, so a reader resuming at 1 continues at the oldest retained item.
        buffer.push("d");
        buffer.push("e");
        assert_eq!(buffer.read_from(1), (2, vec!["c", "d", "e"]));
        assert_eq!(buffer.read_from(4), (4, vec!["e"]));
        assert_eq!(buffer.read_from(9), (5, vec![]));

        // Taken items keep their numbers.
        let _ = buffer.take_all();
        buffer.push("f");
        assert_eq!(buffer.read_from(0), (5, vec!["f"]));
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
