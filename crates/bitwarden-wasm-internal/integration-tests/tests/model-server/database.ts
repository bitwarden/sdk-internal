// Storage for the model server.
//
// Vault items are indexed by owner as well as by id, so serving a sync is a map lookup rather than a
// scan of every item in the database. Owner is a user id for a personal item and an organization id
// for an organization-owned one.

import type { Cipher, Folder, Send } from "@bitwarden/sdk-internal";

import { RevisionClock, type OrganizationEntity, type UserEntity } from "./entities";

/** Ids for items the server creates, so a dump is reproducible without being collision-prone. */
class IdSequence {
  private issued = 0;

  constructor(private readonly prefix: string) {}

  next(): string {
    this.issued += 1;
    return `${this.prefix}${this.issued.toString(16).padStart(4, "0")}-0000-4000-8000-000000000000`;
  }
}

/** A collection of vault items of one kind, indexed by id and by owner. */
class OwnedTable<T> {
  private readonly byId = new Map<string, { ownerId: string; item: T }>();
  private readonly byOwner = new Map<string, Set<string>>();

  constructor(private readonly ids: IdSequence) {}

  /** An id no item in this table holds. */
  newId(): string {
    return this.ids.next();
  }

  get(id: string): T | undefined {
    return this.byId.get(id)?.item;
  }

  set(id: string, ownerId: string, item: T): void {
    const previous = this.byId.get(id);
    if (previous !== undefined && previous.ownerId !== ownerId) {
      this.byOwner.get(previous.ownerId)?.delete(id);
    }

    this.byId.set(id, { ownerId, item });

    let owned = this.byOwner.get(ownerId);
    if (owned === undefined) {
      owned = new Set();
      this.byOwner.set(ownerId, owned);
    }
    owned.add(id);
  }

  /** Replaces an item, keeping its owner. Throws if there is nothing at `id`. */
  update(id: string, item: T): void {
    const stored = this.byId.get(id);
    if (stored === undefined) {
      throw new Error(`no item ${id} to update`);
    }
    stored.item = item;
  }

  remove(id: string): void {
    const stored = this.byId.get(id);
    if (stored === undefined) {
      return;
    }
    this.byOwner.get(stored.ownerId)?.delete(id);
    this.byId.delete(id);
  }

  /** Items belonging to `ownerId`, in insertion order. */
  for(ownerId: string): T[] {
    const owned = this.byOwner.get(ownerId);
    if (owned === undefined) {
      return [];
    }
    return [...owned].flatMap((id) => {
      const stored = this.byId.get(id);
      return stored === undefined ? [] : [stored.item];
    });
  }

  /** Every item, in insertion order. For dumps. */
  all(): T[] {
    return [...this.byId.values()].map((stored) => stored.item);
  }
}

export class Database {
  readonly revisions = new RevisionClock();
  readonly users = new Map<string, UserEntity>();
  readonly organizations = new Map<string, OrganizationEntity>();
  readonly ciphers = new OwnedTable<Cipher>(new IdSequence("bc02"));
  readonly folders = new OwnedTable<Folder>(new IdSequence("bc03"));
  readonly sends = new OwnedTable<Send>(new IdSequence("bc04"));

  user(userId: string): UserEntity {
    const user = this.users.get(userId);
    if (user === undefined) {
      throw new Error(`no user ${userId}; seeded: ${[...this.users.keys()].join(", ")}`);
    }
    return user;
  }

  userByEmail(email: string): UserEntity {
    for (const user of this.users.values()) {
      if (user.email === email) {
        return user;
      }
    }
    const known = [...this.users.values()].map((user) => user.email).join(", ");
    throw new Error(`no user with email ${email}; seeded: ${known}`);
  }

  organization(organizationId: string): OrganizationEntity {
    const organization = this.organizations.get(organizationId);
    if (organization === undefined) {
      throw new Error(`no organization ${organizationId}`);
    }
    return organization;
  }

  /** The organizations `userId` is a member of. */
  organizationsFor(userId: string): OrganizationEntity[] {
    return [...this.organizations.values()].filter((org) => org.members.has(userId));
  }
}
