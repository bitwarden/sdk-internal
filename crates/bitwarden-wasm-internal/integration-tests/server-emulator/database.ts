import { createHash } from "node:crypto";

import type { Send } from "@bitwarden/sdk-internal";

import type { CipherEntity, FolderEntity, OrganizationEntity, UserEntity } from "./entities";

const UUID_INFIX = "-0000-4000-8000-";
const PREFIX_DIGITS = 8;
const SUFFIX_DIGITS = 12;

/**
 * Ids that read as `<purpose>-0000-4000-8000-<counter>`.
 *
 * The purpose is hashed rather than spelled out so every table gets a distinct, stable first block:
 * an id in a failure message says which table issued it, and no two tables can collide.
 */
class SequentialUuidGenerator {
  private readonly prefix: string;
  private issued = 0;

  constructor(purpose: string) {
    this.prefix = createHash("sha256").update(purpose).digest("hex").slice(0, PREFIX_DIGITS);
  }

  next(): string {
    this.issued += 1;
    const uuidSuffix = this.issued.toString(16).padStart(SUFFIX_DIGITS, "0");

    return `${this.prefix}${UUID_INFIX}${uuidSuffix}`;
  }
}

const REVISION_EPOCH = Date.UTC(2025, 0, 1, 0, 0, 0);
const REVISION_STEP_MS = 1000;

/**
 * Stamps writes with a monotonic revision.
 */
class RevisionClock {
  private tick = 0;

  /** The next revision, one second on from the last. */
  next(): string {
    this.tick += 1;
    return this.at(this.tick);
  }

  /** The current revision without advancing, for seeding. */
  current(): string {
    return this.at(this.tick);
  }

  private at(tick: number): string {
    return new Date(REVISION_EPOCH + tick * REVISION_STEP_MS).toISOString().replace(".000Z", "Z");
  }
}

/** A collection of rows of one kind, indexed by id. */
class Table<T> {
  private readonly byId = new Map<string, T>();

  constructor(private readonly ids: SequentialUuidGenerator) {}

  /** An id no item in this table holds. */
  newId(): string {
    return this.ids.next();
  }

  get(id: string): T | undefined {
    return this.byId.get(id);
  }

  set(id: string, item: T): void {
    this.byId.set(id, item);
  }

  /** Replaces an item. Throws if there is nothing at `id`. */
  update(id: string, item: T): void {
    if (!this.byId.has(id)) {
      throw new Error(`no item ${id} to update`);
    }
    this.byId.set(id, item);
  }

  remove(id: string): void {
    this.byId.delete(id);
  }

  /** The items matching `predicate`, in insertion order. */
  filter(predicate: (item: T) => boolean): T[] {
    return [...this.byId.values()].filter(predicate);
  }

  /** Every item, in insertion order. */
  all(): T[] {
    return [...this.byId.values()];
  }
}

export class Database {
  readonly revisions = new RevisionClock();
  readonly users = new Table<UserEntity>(new SequentialUuidGenerator("users"));
  readonly organizations = new Table<OrganizationEntity>(
    new SequentialUuidGenerator("organizations"),
  );
  readonly ciphers = new Table<CipherEntity>(new SequentialUuidGenerator("ciphers"));
  readonly folders = new Table<FolderEntity>(new SequentialUuidGenerator("folders"));
  readonly sends = new Table<Send>(new SequentialUuidGenerator("sends"));
}
