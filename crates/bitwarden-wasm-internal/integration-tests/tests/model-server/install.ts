// Wiring the model servers into `fetch`.
//
// Every route is bound to the origin its server answers on, so a request that goes to the wrong host
// is unmatched rather than quietly served by the other model. Every handler is wrapped in the leak
// inspector, so a secret on the wire is caught wherever it appears — including on routes no test
// thought to look at.

import { installHttpMock, type HttpMock, type Routes } from "../http-mock";

import type { ApiServer } from "./api-server";
import { API_URL } from "./urls";

export interface InstalledServers extends HttpMock {
  /** Requests that went to the API origin. */
  apiRequests(): HttpMock["requests"];
}

export interface InstallOptions {
  api: ApiServer;
  /**
   * Routes layered over the API model, overriding it where the keys collide.
   *
   * This is how a test makes one endpoint fail without disturbing the rest of the model.
   */
  extraRoutes?: Routes;
}

/** Binds every route key in `routes` to `origin`. */
function qualify(routes: Routes, origin: string): Routes {
  return Object.fromEntries(
    Object.entries(routes).map(([key, handler]) => {
      const separator = key.indexOf(" ");
      return [`${key.slice(0, separator)} ${origin}${key.slice(separator + 1)}`, handler];
    }),
  );
}

export function installServers(options: InstallOptions): InstalledServers {
  const { api, extraRoutes = {} } = options;
  const mock = installHttpMock(qualify({ ...api.routes(), ...extraRoutes }, API_URL), {
    onRequest: (request) => api.inspectRequest(request.route, request.body),
  });

  return {
    ...mock,
    apiRequests: () => mock.requests.filter((request) => request.origin === API_URL),
  };
}

export { API_URL, IDENTITY_URL, KEY_CONNECTOR_URL } from "./urls";
