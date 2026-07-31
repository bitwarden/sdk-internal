# Bitwarden Managed Settings Types

Shared data types for the Bitwarden managed-settings framework, principally the
[`ManagementProfile`](crate::ManagementProfile) snapshot of administrator-forced client
configuration and the [`ManagedSettingsError`](crate::ManagedSettingsError) read error.

These types are configuration forced by an operating system's Unified Endpoint Management (UEM/MDM)
channel. They are not Vault Data and involve no cryptography.

This crate deliberately does not depend on `bitwarden-core`. It exists to break a dependency cycle:
`bitwarden-core` must name the shared profile type, while the higher-level handle and override API
in `bitwarden-managed-settings` depend on `bitwarden-core`.
