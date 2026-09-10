// The wire between clients on one device.
//
// The server emulator connects clients that talk to Bitwarden; this connects clients that talk to
// each other. Messages are routed by their destination `Endpoint`, so any number of clients can
// share one bus:
//
//   ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
//   │ DesktopRenderer  │   │ BrowserBackground│   │ Web{tab,document}│
//   └────────┬─────────┘   └────────┬─────────┘   └────────┬─────────┘
//            └──────────────────────┴──────────────────────┘
//                                IpcBus

import {
  IncomingMessage,
  IpcCommunicationBackend,
  type Endpoint,
  type IpcCommunicationBackendSender,
  type OutgoingMessage,
  type Source,
} from "@bitwarden/sdk-internal";

/** The desktop app's renderer process: the top of the shared-unlock hierarchy. */
export const DESKTOP_RENDERER: Source = "DesktopRenderer";

/** The browser extension's background page, addressed relationally. */
export const BROWSER_BACKGROUND: Source = { BrowserBackground: { id: "Own" } };

/** The origin a web client is served from, and the vault url its peers must agree it has. */
export const WEB_ORIGIN = "https://vault.example.com";

/** A web vault tab. Its origin is what scopes which users may be shared with it. */
export const WEB: Source = {
  Web: { tab_id: 1, document_id: "web-vault", origin: WEB_ORIGIN },
};

/** A message that had nowhere to go, for asserting on what was *not* delivered. */
export interface UnroutedMessage {
  source: Source;
  destination: Endpoint;
}

/** The endpoint a source is addressed at. Mirrors `Source::to_endpoint` in `bitwarden-ipc`. */
export function endpointOf(source: Source): Endpoint {
  if (typeof source === "string") {
    return source;
  }
  if ("Web" in source) {
    const { tab_id, document_id } = source.Web;
    return { Web: { tab_id, document_id } };
  }
  return source;
}

/** A stable key for an endpoint, so structural variants can be looked up in a map. */
function endpointKey(endpoint: Endpoint): string {
  if (typeof endpoint === "string") {
    return endpoint;
  }
  if ("Web" in endpoint) {
    return `Web:${endpoint.Web.tab_id}:${endpoint.Web.document_id}`;
  }
  if ("BrowserForeground" in endpoint) {
    return `BrowserForeground:${endpoint.BrowserForeground.id}`;
  }

  const { id } = endpoint.BrowserBackground;
  return `BrowserBackground:${id === "Own" ? "Own" : id.Id}`;
}

/**
 * An in-memory IPC transport shared by several clients.
 *
 * Delivery is synchronous and lossless, so a test that fails is failing on the protocol rather than
 * on the wire. A message addressed to nobody is recorded in {@link unrouted} instead of throwing:
 * a rejection inside a peer's send loop would surface far from the assertion that cares.
 */
export class IpcBus {
  readonly unrouted: UnroutedMessage[] = [];

  private readonly backends = new Map<string, IpcCommunicationBackend>();

  /** Registers `source` on the bus and hands back the backend its IPC client runs on. */
  attach(source: Source): IpcCommunicationBackend {
    const key = endpointKey(endpointOf(source));
    if (this.backends.has(key)) {
      throw new Error(`${key} is already attached to the bus`);
    }

    const sender: IpcCommunicationBackendSender = {
      send: async (outgoing: OutgoingMessage) => this.deliver(source, outgoing),
    };

    const backend = new IpcCommunicationBackend(sender);
    this.backends.set(key, backend);

    return backend;
  }

  /** Takes a client off the bus, as closing it would. Anything sent to it is then unrouted. */
  detach(source: Source): void {
    this.backends.delete(endpointKey(endpointOf(source)));
  }

  private deliver(source: Source, outgoing: OutgoingMessage): void {
    const backend = this.backends.get(endpointKey(outgoing.destination));
    if (backend === undefined) {
      this.unrouted.push({ source, destination: outgoing.destination });
      return;
    }

    backend.receive(
      new IncomingMessage(outgoing.payload, outgoing.destination, source, outgoing.topic),
    );
  }
}
