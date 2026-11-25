import { type ChildProcessWithoutNullStreams, spawn } from "node:child_process";
import { createInterface, type Interface } from "node:readline";

import { hostBinary } from "../../host-binaries";

/**
 * The app's side of the web connector: the SDK's Rust initiator, running in a separate process
 * like it does in the desktop app. The SDK only exports the responder to WASM.
 */
export class RustInitiator {
  private readonly replies: AsyncIterator<string>;

  private constructor(
    private readonly peer: ChildProcessWithoutNullStreams,
    lines: Interface,
  ) {
    this.replies = lines[Symbol.asyncIterator]();
  }

  static spawn(): RustInitiator {
    const peer = spawn(hostBinary("initiator_peer"));
    return new RustInitiator(peer, createInterface({ input: peer.stdout }));
  }

  /** Starts a request and returns the URL the app opens in the browser. */
  async start(connectorUrl: string, request: Uint8Array): Promise<string> {
    return this.send(`start ${connectorUrl} ${Buffer.from(request).toString("base64url")}`);
  }

  /** Decrypts the response from the callback URL. Rejects if it wasn't made for a pending request. */
  async decryptResponse(callbackUrl: string): Promise<Uint8Array> {
    const reply = await this.send(`decrypt ${callbackUrl}`);
    if (!reply.startsWith("ok ")) {
      throw new Error(reply);
    }
    return new Uint8Array(Buffer.from(reply.slice("ok ".length), "base64url"));
  }

  close(): void {
    this.peer.kill();
  }

  private async send(command: string): Promise<string> {
    this.peer.stdin.write(`${command}\n`);
    const reply = await this.replies.next();
    if (reply.done) {
      throw new Error("initiator_peer exited");
    }
    return reply.value;
  }
}
