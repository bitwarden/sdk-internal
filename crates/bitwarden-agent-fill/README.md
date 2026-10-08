# Bitwarden Agent Fill

Internal crate for the bitwarden crate. Do not use.

Seals, opens and verifies the approval requests and responses that let a user approve an agent's
autofill request from another device. Both payloads are sealed as `DataEnvelope`s with the user key,
each under its own `DataEnvelopeNamespace`, so the server only stores opaque strings.

- `AgentFillApprovalClient::create_request` (desktop) seals a request and returns the
  `PendingApproval` the desktop keeps in memory until the request ends.
- `AgentFillApprovalClient::open_request` (any device) unseals a request for display.
- `AgentFillApprovalClient::seal_response` (any device) seals the answer to an opened request.
- `AgentFillApprovalClient::verify_response` (desktop) unseals a response and accepts it only if its
  approval request ID and challenge match the pending request, it hasn't expired, and the decision
  is well formed.
