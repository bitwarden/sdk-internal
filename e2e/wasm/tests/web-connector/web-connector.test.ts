// No Kotlin or Swift counterpart: `WebConnectorResponder` is only exported to WASM, because the
// responder runs in the web vault's connector pages.
import { Connector, WebConnectorResponder, isWebConnectorError } from "@bitwarden/sdk-internal";

import { rejection } from "../utils";
import { RustInitiator } from "./rust-initiator";

const CONNECTOR_URL = "https://vault.bitwarden.com/webauthn-connector.html";
const REQUEST = new TextEncoder().encode('{"challenge":"c2lnbiBtZQ"}');
const RESPONSE = new TextEncoder().encode('{"assertion":"c2lnbmVk"}');

describe("web connector", () => {
  let initiator: RustInitiator;

  beforeEach(() => {
    initiator = RustInitiator.spawn();
  });

  afterEach(() => initiator.close());

  it("returns a response that only the app that made the request can decrypt", async () => {
    // 1. The app starts a request and opens the connector page.
    const requestUrl = await initiator.start(CONNECTOR_URL, REQUEST);

    // 2. The page reads the request and navigates to the callback with its response.
    const responder = WebConnectorResponder.read_request(
      Connector.WebAuthnAssertion,
      new URL(requestUrl).hash,
    );
    const request = responder.request();
    const callbackUrl = responder.encrypt_response(RESPONSE);

    // 3. Verify the page saw the app's request, and the app can decrypt the response.
    expect(request).toEqual(REQUEST);
    expect(callbackUrl).toMatch(/^bitwarden:\/\/webauthn-callback#/);
    expect(await initiator.decryptResponse(callbackUrl)).toEqual(RESPONSE);
  });

  it("returns a response the app rejects when the request was modified", async () => {
    // 1. The app starts a request, and the request is modified on its way to the page.
    const requestUrl = await initiator.start(CONNECTOR_URL, REQUEST);
    const modifiedUrl = withModifiedRequest(requestUrl);

    // 2. The page can't tell, and answers the modified request.
    const responder = WebConnectorResponder.read_request(
      Connector.WebAuthnAssertion,
      new URL(modifiedUrl).hash,
    );
    const callbackUrl = responder.encrypt_response(RESPONSE);

    // 3. Verify the app can't decrypt the response.
    await expect(initiator.decryptResponse(callbackUrl)).rejects.toThrow("Handshake failed");
  });

  it("rejects a request without the app's public key", async () => {
    // 1. The page is opened with a request that has a state but no request parameter.
    const fragment = new URLSearchParams({ state: "A".repeat(43) }).toString();

    // 2. Verify the page rejects it.
    const error = await rejection(
      Promise.resolve().then(() =>
        WebConnectorResponder.read_request(Connector.WebAuthnAssertion, fragment),
      ),
      isWebConnectorError,
    );
    expect(error.variant).toBe("MalformedParameter");
  });
});

/** Flips one bit of the last request byte, leaving the app's public key intact. */
function withModifiedRequest(requestUrl: string): string {
  const url = new URL(requestUrl);
  const params = new URLSearchParams(url.hash.slice(1));
  const message = Buffer.from(params.get("request") ?? "", "base64url");
  message[message.length - 1] ^= 1;
  params.set("request", message.toString("base64url"));
  url.hash = params.toString();
  return url.toString();
}
