import type { ActionPolicy } from "../actions.mjs";
import type { Authorizer, OrganizationPrincipal } from "../contracts.js";
export type SqlValue = string | number | null;
export type SqlStorage = {
  exec(
    query: string,
    ...bindings: SqlValue[]
  ): { toArray(): Record<string, SqlValue>[] };
};
export type LedgerStorage = {
  sql: SqlStorage;
  transactionSync<T>(callback: () => T): T;
  sync(): Promise<void>;
};
/** Trusted object-local authority; revision changes atomically with all local authority state. */
export type LocalAuthority = {
  revision(): string;
  policy(): ActionPolicy;
  allows(principal: OrganizationPrincipal): boolean;
  authorize: Authorizer;
};
