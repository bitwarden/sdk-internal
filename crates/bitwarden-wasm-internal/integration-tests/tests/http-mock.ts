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
  /** Scheme and host the request went to, e.g. `http://localhost:4000`. */
  origin: string;
  /** Pathname only, e.g. `/organizations/<id>/private-key`. */
  path: string;
  /** `${method} ${path}` — the key format used by {@link Routes}. */
  route: string;
  /**
   * Values captured by a `:name` segment of the matched route key, e.g. `{ id: "…" }` for
   * `PUT /ciphers/:id`. Empty for a literal route.
   */
  params: Record<string, string>;
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

/**
 * Route handlers keyed by `"<METHOD> <pathname>"`.
 *
 * A key may contain `:name` segments, which match one path segment each and land in
 * {@link MockRequest.params}: `"PUT /ciphers/:id"` matches `PUT /ciphers/abc`. Literal keys are
 * matched first, so a specific route always beats a pattern that would also match it — `"PUT
 * /ciphers/:id/restore"` and `"PUT /ciphers/:id"` can coexist because the segment counts differ, and
 * `"GET /folders/all"` still wins over `"GET /folders/:id"`.
 *
 * A key may also be qualified with an origin — `"GET http://localhost:4001/user-keys"` — in which case
 * it only matches requests to that host. This is what lets two backends on different origins own the
 * same path without one silently answering for the other. An unqualified key matches any origin.
 */
export type Routes = Record<string, RouteHandler>;

interface CompiledRoute {
  method: string;
  /** Set when the key was origin-qualified, in which case only that origin matches. */
  origin: string | undefined;
  segments: string[];
  handler: RouteHandler;
}

/** Splits a route key into its method, optional origin and path. */
function splitKey(key: string): { method: string; origin: string | undefined; path: string } {
  const separator = key.indexOf(" ");
  const method = key.slice(0, separator);
  const rest = key.slice(separator + 1);

  if (rest.startsWith("http")) {
    const url = new URL(rest);
    return { method, origin: url.origin, path: url.pathname };
  }
  return { method, origin: undefined, path: rest };
}

/** Splits pattern keys out of `routes`, leaving literal keys to exact lookup. */
function compilePatterns(routes: Routes): CompiledRoute[] {
  return Object.entries(routes)
    .filter(([key]) => key.includes("/:"))
    .map(([key, handler]) => {
      const { method, origin, path } = splitKey(key);
      return { method, origin, segments: path.split("/"), handler };
    });
}

/** Matches `path` against a compiled pattern, returning captured params or `undefined`. */
function matchPattern(
  route: CompiledRoute,
  method: string,
  path: string,
  origin: string,
): Record<string, string> | undefined {
  if (route.method !== method) {
    return undefined;
  }
  if (route.origin !== undefined && route.origin !== origin) {
    return undefined;
  }
  const actual = path.split("/");
  if (actual.length !== route.segments.length) {
    return undefined;
  }

  const params: Record<string, string> = {};
  for (const [index, segment] of route.segments.entries()) {
    if (segment.startsWith(":")) {
      params[segment.slice(1)] = decodeURIComponent(actual[index]);
    } else if (segment !== actual[index]) {
      return undefined;
    }
  }
  return params;
}

export interface HttpMockOptions {
  /**
   * Only answer requests to this origin, e.g. `http://localhost:4000`. Anything else is recorded as
   * unmatched. Omit to answer every origin, which is what the pre-existing callers expect.
   */
  origin?: string;
}

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
export function installHttpMock(routes: Routes, options: HttpMockOptions = {}): HttpMock {
  const originalFetch = globalThis.fetch;
  const requests: MockRequest[] = [];
  const unmatched: MockRequest[] = [];
  const patterns = compilePatterns(routes);

  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = input instanceof Request ? input.url : input.toString();
    const method = (
      input instanceof Request ? input.method : (init?.method ?? "GET")
    ).toUpperCase();
    const parsed = new URL(url);
    const path = parsed.pathname;
    const body = await readBody(input, init);

    const request: MockRequest = {
      method,
      url,
      origin: parsed.origin,
      path,
      route: `${method} ${path}`,
      params: {},
      body,
      json: <T>() => JSON.parse(body) as T,
    };
    requests.push(request);

    // Requests to another origin are not this mock's to answer. Without this the key connector and
    // the API would share one namespace, and `/user-keys` would match whichever was declared.
    if (options.origin !== undefined && parsed.origin !== options.origin) {
      unmatched.push(request);
      return makeResponse(url, {
        status: 501,
        json: { message: `request to unexpected origin ${parsed.origin}` },
      });
    }

    // Origin-qualified literals first, then unqualified literals, then patterns. Literals always beat
    // a pattern that would also match, and a route pinned to an origin beats an unpinned one.
    let handler = routes[`${method} ${parsed.origin}${path}`] ?? routes[request.route];
    if (handler === undefined) {
      for (const pattern of patterns) {
        const params = matchPattern(pattern, method, path, parsed.origin);
        if (params !== undefined) {
          request.params = params;
          handler = pattern.handler;
          break;
        }
      }
    }

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
