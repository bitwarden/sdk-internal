// A `globalThis.fetch` stub for exercising SDK methods that call the API, with recording so tests
// can assert which routes were hit and what was posted.
//
// The SDK's HTTP client is reqwest compiled to wasm, which has two habits worth knowing about:
// it hands `fetch` a `Request` object rather than an `(url, init)` pair, and it parses
// `Response.url` on every response — including error and empty ones — so a response built with
// `new Response(...)`, whose `url` is `""`, makes it throw instead of returning an error.

/** A request the SDK made, as recorded by the mock. */
export interface MockRequest {
  method: string;
  url: string;
  /** Pathname only, e.g. `/organizations/<id>/private-key`. */
  path: string;
  /** `${method} ${path}` — the key format used by {@link Routes}. */
  route: string;
  /** Raw body, `""` for requests without one. */
  body: string;
  json<T = any>(): T;
}

/** What a route handler returns. The mock turns it into a `Response`. */
export interface MockReply {
  /** Defaults to 200. */
  status?: number;
  /** Serialized as JSON with a matching content type. */
  json?: unknown;
  /** Raw body, sent as-is. Omit both `json` and `text` for an empty response. */
  text?: string;
}

export type RouteHandler = (request: MockRequest) => MockReply | Promise<MockReply>;

/** Route handlers keyed by `"<METHOD> <pathname>"`, matched exactly. */
export type Routes = Record<string, RouteHandler>;

export interface HttpMock {
  /** Every request the SDK made, in order. */
  readonly requests: MockRequest[];
  /** Requests that matched no route. Assert this is empty. */
  readonly unmatched: MockRequest[];
  /** The routes that were requested, in order. */
  routes(): string[];
  /** Parsed body of the single request to `route`; throws unless exactly one was made. */
  bodyFor(route: string): any;
  called(route: string): boolean;
  /** Puts the original `fetch` back. */
  restore(): void;
}

function makeResponse(url: string, reply: MockReply): Response {
  const body = reply.json !== undefined ? JSON.stringify(reply.json) : (reply.text ?? null);
  const response = new Response(body, {
    status: reply.status ?? 200,
    headers: reply.json !== undefined ? { "Content-Type": "application/json" } : {},
  });
  // `new Response(...)` leaves `url` empty, which reqwest's wasm client cannot parse.
  Object.defineProperty(response, "url", { value: url });
  return response;
}

async function readBody(input: RequestInfo | URL, init?: RequestInit): Promise<string> {
  if (input instanceof Request) {
    // The body is a single-use stream, so this must happen exactly once per request.
    return await input.text();
  }
  return typeof init?.body === "string" ? init.body : "";
}

/**
 * Replaces `globalThis.fetch` with a stub serving `routes`. Call {@link HttpMock.restore} in
 * `afterEach`.
 *
 * Requests matching no route are recorded in {@link HttpMock.unmatched} and answered with a 501
 * rather than throwing: a throw inside the stub reaches the SDK as a transport failure and
 * disguises the missing route as an ordinary API error.
 */
export function installHttpMock(routes: Routes): HttpMock {
  const originalFetch = globalThis.fetch;
  const requests: MockRequest[] = [];
  const unmatched: MockRequest[] = [];

  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = input instanceof Request ? input.url : input.toString();
    const method = (
      input instanceof Request ? input.method : (init?.method ?? "GET")
    ).toUpperCase();
    const path = new URL(url).pathname;
    const body = await readBody(input, init);

    const request: MockRequest = {
      method,
      url,
      path,
      route: `${method} ${path}`,
      body,
      json: <T>() => JSON.parse(body) as T,
    };
    requests.push(request);

    const handler = routes[request.route];
    if (handler === undefined) {
      unmatched.push(request);
      return makeResponse(url, {
        status: 501,
        json: { message: `unmocked route ${request.route}` },
      });
    }

    return makeResponse(url, await handler(request));
  };

  return {
    requests,
    unmatched,
    routes: () => requests.map((request) => request.route),
    bodyFor: (route) => {
      const matching = requests.filter((request) => request.route === route);
      if (matching.length !== 1) {
        throw new Error(`expected exactly 1 request to ${route}, got ${matching.length}`);
      }
      return matching[0].json();
    },
    called: (route) => requests.some((request) => request.route === route),
    restore: () => {
      globalThis.fetch = originalFetch;
    },
  };
}
