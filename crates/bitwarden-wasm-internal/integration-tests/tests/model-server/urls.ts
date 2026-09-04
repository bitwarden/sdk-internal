// The origins the model servers answer on.
//
// Nothing listens on either port; both are served entirely by the `fetch` mock. Concrete hosts keep
// the SDK's request URLs parseable and make an unmocked route fail loudly rather than escape to the
// network.

export const API_URL = "http://localhost:4000";
export const IDENTITY_URL = `${API_URL}/identity`;
export const KEY_CONNECTOR_URL = "http://localhost:4001";
