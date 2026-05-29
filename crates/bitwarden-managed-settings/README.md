# Bitwarden Managed Settings

IT-admin-forced (centrally managed) client settings. Owns *resolution* of managed
configuration delivered via OS-mediated channels (Apple managed app config,
Android `RestrictionsManager`, Windows `HKLM\SOFTWARE\Policies`, Linux
`/etc/bitwarden/policies`, Chromium `chrome.storage.managed`).

The SDK does not vary behavior by acquisition source. Presence of a key
implies the key is forced.
