/** Internal contracts for validated JSON entering synchronous policy modules. */
export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };
export type ReplayEnvelope = { session: string; sender: string; id: string } & Record<string, JsonValue>;
export type ReplayDecision =
  | { status: "new" | "duplicate" | "conflict" }
  | { status: "full"; retryAfter: number };
