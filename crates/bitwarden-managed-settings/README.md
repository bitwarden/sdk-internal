# Bitwarden Managed Settings

Provides [`ManagedSettingsClient`], the SDK's read handle onto the settings an organization's IT
administrators enforce through the host operating system's Unified Endpoint Management (UEM)
channel.

The host application constructs a [`ManagedSettingsClient`] at startup with
[`ManagedSettingsClient::new`], acquires a [`ManagementProfile`] from the host platform, and pushes
it in with [`ManagedSettingsClient::update_profile`]. Passing `None` clears the profile. Clones of
the handle share one profile, so an update pushed through any clone is observed by all of them.

The same shared cell — obtained from [`ManagedSettingsClient::cell`] — is handed to
[`bitwarden_core::ClientBuilder::with_managed_profile`], so SDK feature crates read the current
profile through [`ManagedSettingsClientExt::managed_settings`] on a [`bitwarden_core::Client`]. A
client built without a cell gets a fresh empty one and simply manages nothing.

Consumers read a value with [`ManagedSettingsClient::get`] for the raw JSON-encoded string, or
decode it into a concrete type with [`ManagementProfile::get_as`] on the profile returned by
[`ManagedSettingsClient::current_profile`]. Guard writes to the corresponding state with
[`ManagedSettingsClient::is_managed`], only writing when the key is not administrator-forced.

The first profile push is asynchronous on every platform, so a consumer may not observe a managed
setting immediately after startup.

A managed setting overrides user and global state and built-in defaults. It carries no automatic
precedence over an enterprise policy — where a policy and a managed setting both bear on one
effective setting, the consuming feature is responsible for resolving the conflict.
