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
  /** Values captured by the `:name` segments of the route that matched, empty for literal routes. */
  params: Record<string, string>;
  /** Raw body, `""` for requests without one. */
  body: string;
  json<T = unknown>(): T;
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
 * Route handlers keyed by `"<METHOD> <path>"`.
 *
 * The path may be origin-qualified (`"GET http://localhost:4001/user-keys"`) to bind a route to one
 * server, and may contain `:name` segments (`"PUT /ciphers/:id"`) captured into
 * {@link MockRequest.params}.
 *
 * Resolution is origin-qualified literal, then bare literal, then patterns in declaration order — so
 * `"GET /folders/all"` wins over `"GET /folders/:id"` regardless of which was declared first.
 */
export type Routes = Record<string, RouteHandler>;

export interface HttpMock {
  /** Every request the SDK made, in order. */
  readonly requests: MockRequest[];
  /** Requests that matched no route. Assert this is empty. */
  readonly unmatched: MockRequest[];
  /** The routes that were requested, in order. */
  routes(): string[];
  /**
   * Parsed body of the single request to `route`; throws unless exactly one was made.
   *
   * Pass the route's request DTO. The default is deliberately loose so a test that only reaches for
   * one field does not have to name a type, but new code should name one.
   */
  bodyFor<T = Record<string, any>>(route: string): T;
  called(route: string): boolean;
  /** Puts the original `fetch` back. */
  restore(): void;
}

/** A route key split into the parts the matcher compares against. */
interface CompiledRoute {
  handler: RouteHandler;
  method: string;
  /** Bound origin, or `undefined` for a route that answers on any origin. */
  origin: string | undefined;
  /** Path split on `/`; a segment starting with `:` captures. */
  segments: string[];
}

/** Splits `"PUT http://host/a/:b"` into its method, optional origin and path. */
function splitKey(key: string): { method: string; origin: string | undefined; path: string } {
  const separator = key.indexOf(" ");
  const method = key.slice(0, separator);
  const rest = key.slice(separator + 1);

  if (!rest.startsWith("http")) {
    return { method, origin: undefined, path: rest };
  }

  const url = new URL(rest);
  return { method, origin: url.origin, path: url.pathname };
}

/** Compiles only the keys that capture; literal keys stay on the fast object lookup. */
function compilePatterns(routes: Routes): CompiledRoute[] {
  return Object.entries(routes)
    .filter(([key]) => key.includes("/:"))
    .map(([key, handler]) => {
      const { method, origin, path } = splitKey(key);
      return { handler, method, origin, segments: path.split("/") };
    });
}

/** Captured params if `route` matches, `undefined` otherwise. */
function matchPattern(
  route: CompiledRoute,
  method: string,
  path: string,
  origin: string,
): Record<string, string> | undefined {
  if (route.method !== method || (route.origin !== undefined && route.origin !== origin)) {
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
      continue;
    }
    if (segment !== actual[index]) {
      return undefined;
    }
  }
  return params;
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

export interface HttpMockOptions {
  /**
   * Called for every request before it is routed, matched or not.
   *
   * Used to police request bodies centrally, so an invariant holds on routes no test thought to
   * look at.
   */
  onRequest?: (request: MockRequest) => void;
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
    options.onRequest?.(request);

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
        json: { message: `unmocked route ${request.route} on ${parsed.origin}` },
      });
    }

    return makeResponse(url, await handler(request));
  };

  return {
    requests,
    unmatched,
    routes: () => requests.map((request) => request.route),
    bodyFor: <T>(route: string) => {
      const matching = requests.filter((request) => request.route === route);
      if (matching.length !== 1) {
        throw new Error(`expected exactly 1 request to ${route}, got ${matching.length}`);
      }
      return matching[0].json<T>();
    },
    called: (route) => requests.some((request) => request.route === route),
    restore: () => {
      globalThis.fetch = originalFetch;
    },
  };
}
