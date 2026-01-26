//! Scene wrapper for test data

use std::collections::HashMap;

use super::SceneTemplate;

/// A scene containing test data created by the seeder
///
/// The scene wraps a template instance with the server response data.
/// Cleanup is handled by the owning `Play` instance when it is dropped.
pub struct Scene<T: SceneTemplate> {
    /// The template instance with populated data
    template: T,
    /// Map of original IDs to mangled IDs for test isolation
    mangle_map: HashMap<String, String>,
}

impl<T: SceneTemplate> Scene<T> {
    /// Create a new scene wrapper
    pub(crate) fn new(template: T, mangle_map: HashMap<String, String>) -> Self {
        Self {
            template,
            mangle_map,
        }
    }

    /// Access the underlying template
    pub fn inner(&self) -> &T {
        &self.template
    }

    /// Get the mangled value for a given key
    pub fn get_mangled(&self, key: &str) -> Option<&str> {
        self.mangle_map.get(key).map(|s| s.as_str())
    }
}
