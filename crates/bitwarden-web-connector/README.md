# bitwarden-web-connector

One-shot encrypted response channel for redirect-based flows, where an app opens a web page in the
browser and the page returns its result to the app through a callback URL (e.g. login with passkey).

The channel is a Noise NN handshake (`Noise_NN_P256_AESGCM_SHA256`):

1. The app (initiator) calls `PendingInitiator::start`, stores the `PendingInitiator` by its
   `State`, and opens the returned URL. The request parameters travel in the URL fragment in
   plaintext, together with the app's ephemeral public key.
2. The page (responder) calls `PendingResponder::read_request`, uses the request parameters, and
   navigates to the URL returned by `PendingResponder::encrypt_response`.
3. The app reads the `State` from the callback, looks up the pending request, and calls
   `PendingInitiator::decrypt_response`.

The connector and state are bound into the handshake prologue. The callback URL is always
`bitwarden://<connector path>#<response>`, derived from the `Connector` and never supplied by the
request.

On `ASWebAuthenticationSession` on macOS and iOS, and AuthTabs on Android should be used to open the
connector page, which ensures that the response always goes to the initiating app, even if an
attacker attempts to hijack the `bitwarden://` scheme.

On other OSes, the app must be registered as the handler for the `bitwarden://` scheme; users
running builds that aren't installed (e.g. AppImages or local dev builds) must register it
themselves.

Web pages use the responder through `WebConnectorResponder` in `@bitwarden/sdk-internal`.

## Threat model

- In scope:
  - Passive observers of the request and/or callback URL (other processes and users reading argv,
    browser history, logs) can't decrypt the response to a request that the app started.
  - A remote attacker who crafts a request URL can't receive the response, since the callback always
    leads back to the user's own device.
- Out of scope:
  - A local attacker who can initiate a request and receive encrypted responses locally (e.g. by
    registering the scheme handler) can decrypt the response. (This would also apply if a browser or
    OS logs callback responses, but no known implementation does that today.) A local attacker can
    phish the response from the user.
  - An attacker who can read the request can complete with their own response. Consumers must verify
    the response (e.g. on the server), and should treat a second callback for the same `State` as
    suspicious.
