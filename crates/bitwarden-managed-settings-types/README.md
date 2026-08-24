# Bitwarden Managed Settings Types

Contains the shared data types for managed settings — configuration an organization's IT
administrators enforce through the host operating system's Unified Endpoint Management (UEM)
channel.

[`ManagementProfile`] is a point-in-time snapshot of that configuration: a schema
[`version`](ManagementProfile::version), an [`updated_at`](ManagementProfile::updated_at) timestamp
recording when the host last refreshed it, and a [`settings`](ManagementProfile::settings) map of
dotted keys (e.g. `"environment.base"`) to JSON-encoded value strings. Values are stored as plain
`String` rather than `serde_json::Value` because `String` has a UniFFI representation; callers
decode on demand.

Read a profile with [`ManagementProfile::is_managed`] to test whether a key is administrator-forced,
[`ManagementProfile::get`] for the raw JSON-encoded string, or [`ManagementProfile::get_as`] to
decode into a concrete type — which fails with [`ManagedSettingsError::Decode`] when the stored
value does not match the requested shape. [`ManagementProfile::empty`] builds a profile that manages
nothing.

This crate exists separately from `bitwarden-managed-settings` to break a dependency cycle:
`bitwarden-core` must name [`ManagementProfile`] to hold the shared profile cell, while the
higher-level `ManagedSettingsClient` handle depends on `bitwarden-core`.

Managed settings are administrator-supplied client configuration. They are not Vault Data, involve
no cryptography, and carry no key material.
