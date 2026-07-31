# Bitwarden Managed Settings

The host-facing handle for the Bitwarden managed-settings framework. Provides
[`ManagedSettingsClient`](crate::ManagedSettingsClient), a cloneable handle over the shared
in-memory management profile, and [`ManagedSettingsClientExt`](crate::ManagedSettingsClientExt),
which reads that handle back off a constructed `bitwarden-core` `Client`.

The host application acquires a profile from the operating system's Unified Endpoint Management
(UEM/MDM) channel, normalizes it into a
[`ManagementProfile`](bitwarden_managed_settings_types::ManagementProfile), and pushes it into the
shared cell through `update_profile`. The SDK and other clients read the same cell. Presence of a
key means the value is administrator-forced; reads fail closed to "unmanaged" when no profile is
present.

Managed settings are client configuration, not Vault Data, and involve no cryptography.
