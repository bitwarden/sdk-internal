// Reading the email a live server sends to a test account.
//
// The mail server is an Inbucket instance that accepts mail for every address at its domain and
// keeps it in memory only. Each mailbox is named after the local part of the address, so a random
// local part gives a test a mailbox of its own.

import { MAIL_API_URL } from "./config";

/** How long the server may take to deliver a message. Delivery goes out through a mail provider. */
const DEFAULT_TIMEOUT_MS = 60_000;

const POLL_INTERVAL_MS = 1_000;

/** A received message, with only the fields a test reads. */
export interface Email {
  id: string;
  subject: string;
  /** The plain-text body. */
  text: string;
}

/** A message as `GET <MAIL_API_URL>/<address>` lists it. */
interface MessageHeader {
  id: string;
  subject: string;
  "posix-millis": number;
}

/** A message as `GET <MAIL_API_URL>/<address>/<id>` returns it. */
interface Message extends MessageHeader {
  body: { text: string; html: string };
}

export class Mailbox {
  private constructor(readonly address: string) {}

  /** A mailbox at a random address that no other test uses. */
  static random(): Mailbox {
    return new Mailbox(`${crypto.randomUUID()}@${new URL(MAIL_API_URL).host}`);
  }

  /**
   * The newest message with a matching subject. Waits for one to arrive.
   *
   * Throws after `timeoutMs` without a match, and names the subjects that did arrive.
   */
  async waitFor(subject: string | RegExp, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<Email> {
    const matches = (header: MessageHeader) =>
      typeof subject === "string" ? header.subject === subject : subject.test(header.subject);

    const deadline = Date.now() + timeoutMs;
    let received: MessageHeader[] = [];
    for (;;) {
      received = await this.get<MessageHeader[]>("");

      const newest = received
        .filter(matches)
        .sort((a, b) => b["posix-millis"] - a["posix-millis"])[0];
      if (newest !== undefined) {
        const message = await this.get<Message>(`/${encodeURIComponent(newest.id)}`);

        return { id: message.id, subject: message.subject, text: message.body.text };
      }

      if (Date.now() >= deadline) {
        break;
      }

      await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
    }

    const subjects = received.map((header) => JSON.stringify(header.subject)).join(", ");
    throw new Error(
      `no message matching ${String(subject)} reached ${this.address} within ${timeoutMs} ms; ` +
        `received: ${subjects === "" ? "nothing" : subjects}`,
    );
  }

  private async get<T>(path: string): Promise<T> {
    const url = `${MAIL_API_URL}/${encodeURIComponent(this.address)}${path}`;
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`GET ${url} answered ${response.status}: ${await response.text()}`);
    }

    return (await response.json()) as T;
  }
}
