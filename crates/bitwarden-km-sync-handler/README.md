# bitwarden-km-sync-handler

Temporary sync handler will live in this crate until sync fully moves to the SDK. At that point this
logic will be moved over.

Holds the key management work that has to happen on every sync. Today the clients still own sync, so
they call the handler imperatively with the parts of the sync response it cares about. Once the SDK
owns sync, the `SyncHandler` implementation in this crate becomes the entry point instead and the
imperative surface goes away.

Currently the handler reports the key id of the current user key to the server when the server does
not already know it.
