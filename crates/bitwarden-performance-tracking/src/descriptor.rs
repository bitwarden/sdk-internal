//! Identifies a single performance event.

use std::borrow::Cow;

/// The three names identifying an event, plus the properties known before it runs.
///
/// The names form a hierarchy in the DevTools performance panel: `namespace` is the track group,
/// `category` is the track, and `name` labels the entry itself.
///
/// ```text
/// Unlock                    <- namespace, generally the team owning the domain
///  └─ UnlockClient          <- category, generally the type doing the work
///      └─ unlock            <- name
/// ```
// The fields are read only by the wasm backend, which is the point of the crate; off wasm they are
// deliberately built and dropped.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
pub struct PerformanceEventDescriptor {
    pub(crate) namespace: Cow<'static, str>,
    pub(crate) category: Cow<'static, str>,
    pub(crate) name: String,
    pub(crate) properties: Vec<(String, String)>,
}

impl PerformanceEventDescriptor {
    /// Describes an event named `name`, to be drawn on the `category` lane of the `namespace` track
    /// group. Both the group and the track are created by DevTools on first use.
    pub fn new(
        namespace: impl Into<Cow<'static, str>>,
        category: impl Into<Cow<'static, str>>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            category: category.into(),
            name: name.into(),
            properties: Vec::new(),
        }
    }

    /// Adds a key/value row to the details pane DevTools shows for the selected entry.
    ///
    /// The value is rendered verbatim, so it must never carry key material or vault data.
    pub fn prop(mut self, key: &str, value: impl std::fmt::Display) -> Self {
        self.properties.push((key.to_owned(), value.to_string()));
        self
    }

    /// The label DevTools shows on the entry, which names the track it sits on so an entry stays
    /// readable once copied out of the timeline.
    pub(crate) fn entry_name(&self) -> String {
        format!("[{}]: {}", self.category, self.name)
    }
}
