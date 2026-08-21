// Installs one or both model servers into `globalThis.fetch`, dispatching by origin.
//
// There is only one `fetch` to replace, so each server's routes are qualified with the origin that
// owns them and handed to a single mock. That is what keeps the two models genuinely separate: a
// `/user-keys` request sent to the API origin matches nothing and lands in `unmatched`, rather than
// being quietly answered by the key connector.

import { installHttpMock, type HttpMock, type Routes } from "../http-mock";

import type { ApiServer } from "./api-server";
import type { KeyConnectorServer } from "./key-connector-server";
import { API_URL, KEY_CONNECTOR_URL } from "./urls";

export { API_URL, KEY_CONNECTOR_URL } from "./urls";

export interface InstalledServers extends HttpMock {
  /** Requests that reached the API model. */
  apiRequests(): HttpMock["requests"];
  /** Requests that reached the key connector model. */
  keyConnectorRequests(): HttpMock["requests"];
}

export interface InstallOptions {
  api?: ApiServer;
  keyConnector?: KeyConnectorServer;
  /** Extra routes on the API origin, for an endpoint the model does not cover. */
  extraRoutes?: Routes;
}

/**
 * Rewrites `"GET /path"` keys as `"GET <origin>/path"`, and routes every request past the secret
 * inspector on the way in.
 *
 * Inspecting centrally is the point: a test cannot forget to check, and it covers the key connector's
 * requests as well as the API's.
 */
function qualify(routes: Routes, origin: string, api: ApiServer | undefined): Routes {
  return Object.fromEntries(
    Object.entries(routes).map(([key, handler]) => {
      const separator = key.indexOf(" ");
      const qualified = `${key.slice(0, separator)} ${origin}${key.slice(separator + 1)}`;
      const guarded: Routes[string] = (request) => {
        api?.inspectRequest(request.route, request.body);
        return handler(request);
      };
      return [qualified, guarded];
    }),
  );
}

/**
 * Replaces `fetch` with a stub backed by the supplied models. Call `restore()` in `afterEach`.
 *
 * `unmatched` behaves as it always has, so the existing "every request was accounted for" assertion
 * keeps working — and now also catches a request sent to the wrong origin.
 */
export function installServers(options: InstallOptions): InstalledServers {
  const routes: Routes = {
    ...(options.api === undefined
      ? {}
      : qualify({ ...options.api.routes(), ...(options.extraRoutes ?? {}) }, API_URL, options.api)),
    ...(options.keyConnector === undefined
      ? {}
      : qualify(options.keyConnector.routes(), KEY_CONNECTOR_URL, options.api)),
  };

  const mock = installHttpMock(routes);
  const from = (origin: string) => () => mock.requests.filter((r) => r.origin === origin);

  return Object.assign(mock, {
    apiRequests: from(API_URL),
    keyConnectorRequests: from(KEY_CONNECTOR_URL),
  });
}
