/**
 * Experimental XEIP v0.1 TypeScript reference SDK.
 * Validation is structural only; sender strings are not verified identities.
 */
import { validateEnvelope, validateEntity, validateSession, validateCapability, requireUri } from "./validation.js";
import { SseParser } from "./sse.js";

export const XEIP_VERSION = "0.1" as const;

export type EntityKind = "human" | "agent" | "machine" | "service";
export type MessageKind = "message" | "event" | "command" | "receipt";
export type SessionMode = "direct" | "group";

export interface Capability {
  id: string;
  description?: string;
  spec?: string;
}
export interface Endpoint {
  transport: "http-sse" | "http" | "websocket" | "local" | "webrtc" | "a2a" | "mcp";
  url: string;
}
export interface Entity {
  xeip: typeof XEIP_VERSION;
  id: string;
  name?: string;
  kinds: EntityKind[];
  endpoints?: Endpoint[];
  capabilities?: Capability[];
  extensions?: Record<string, unknown>;
}
export interface Session {
  xeip: typeof XEIP_VERSION;
  id: string;
  mode: SessionMode;
  members: string[];
  createdAt: string;
  extensions?: Record<string, unknown>;
}
export interface Envelope {
  xeip: typeof XEIP_VERSION;
  id: string;
  kind: MessageKind;
  sender: string;
  recipient?: string;
  session: string;
  timestamp: string;
  body: { contentType: string; data: unknown };
  replyTo?: string;
  expiresAt?: string;
  extensions?: Record<string, unknown>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!isRecord(value)) throw new TypeError(label + " must be an object");
  return value;
}
export function assertEnvelope(value: unknown): asserts value is Envelope {
  validateEnvelope(value);
}
export function assertEntity(value: unknown): asserts value is Entity {
  validateEntity(value);
}
export function assertSession(value: unknown): asserts value is Session {
  validateSession(value);
}
export function assertCapability(value: unknown): asserts value is Capability {
  validateCapability(value);
}

export function makeMessage(options: Omit<Envelope, "xeip" | "id" | "timestamp"> & { id?: string; timestamp?: string }): Envelope {
  const message: Envelope = {
    xeip: XEIP_VERSION,
    id: options.id ?? "urn:uuid:" + crypto.randomUUID(),
    kind: options.kind,
    sender: options.sender,
    session: options.session,
    timestamp: options.timestamp ?? new Date().toISOString(),
    body: options.body
  };
  if (options.recipient !== undefined) message.recipient = options.recipient;
  if (options.replyTo !== undefined) message.replyTo = options.replyTo;
  if (options.expiresAt !== undefined) message.expiresAt = options.expiresAt;
  if (options.extensions !== undefined) message.extensions = options.extensions;
  assertEnvelope(message);
  return message;
}

export interface XeipClientOptions {
  baseUrl: string;
  token: string;
  fetchImpl?: typeof fetch;
}

export interface SendAcceptance {
  accepted: true;
  /** Number of new writes to active streams, not recipient acknowledgments. */
  delivered: number;
  /** Present when the relay selected the optional local replay profile. */
  duplicate?: boolean;
  /** Per-session delivery sequence, present when the local delivery profile is enabled. */
  seq?: number;
}

export interface ReceiptAcceptance {
  acknowledged: true;
  session: string;
  seq: number;
  duplicate: boolean;
}

export class XeipHttpSseClient {
  private readonly baseUrl: string;
  private readonly token: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: XeipClientOptions) {
    if (!options.token) throw new TypeError("development token is required");
    const url = new URL(options.baseUrl);
    if (!["http:", "https:"].includes(url.protocol)) throw new TypeError("HTTP(S) base URL required");
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.token = options.token;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async send(message: Envelope): Promise<SendAcceptance> {
    assertEnvelope(message);
    const response = await this.fetchImpl(this.baseUrl + "/messages", {
      method: "POST",
      headers: { "Authorization": "Bearer " + this.token, "Content-Type": "application/json" },
      body: JSON.stringify(message)
    });
    if (response.status !== 202) {
      await response.body?.cancel().catch(() => {});
      throw new Error("XEIP relay rejected message: HTTP " + response.status);
    }
    const result: unknown = await response.json();
    const responseBody = requireRecord(result, "relay response");
    const delivered = responseBody.delivered;
    if (responseBody.accepted !== true || typeof delivered !== "number" || !Number.isSafeInteger(delivered) || delivered < 0) {
      throw new TypeError("invalid relay response");
    }
    const acceptance: SendAcceptance = { accepted: true, delivered };
    if (Object.hasOwn(responseBody, "duplicate")) {
      const duplicate = responseBody.duplicate;
      if (typeof duplicate !== "boolean" || (duplicate && delivered !== 0)) throw new TypeError("invalid relay response");
      acceptance.duplicate = duplicate;
    }
    if (Object.hasOwn(responseBody, "seq")) {
      const seq = responseBody.seq;
      if (!Number.isSafeInteger(seq) || (seq as number) < 0) throw new TypeError("invalid relay response");
      acceptance.seq = seq as number;
    }
    return acceptance;
  }

  /**
   * Acknowledges a retained delivery for `session` under the optional
   * local-receipts profile. At least one of `seq`/`id` must be supplied.
   */
  async acknowledge(session: string, target: { seq?: number; id?: string; status?: "received" }, signal?: AbortSignal): Promise<ReceiptAcceptance> {
    requireUri(session, "session");
    const selector = requireRecord(target, "receipt target");
    for (const key of Object.keys(selector)) {
      if (key !== "seq" && key !== "id" && key !== "status") throw new TypeError("unexpected field: " + key);
    }
    if (target.seq === undefined && target.id === undefined) throw new TypeError("receipt requires seq or id");
    const body: Record<string, unknown> = { session };
    if (target.seq !== undefined) {
      if (!Number.isSafeInteger(target.seq) || target.seq < 0) throw new TypeError("seq must be a non-negative safe integer");
      body.seq = target.seq;
    }
    if (target.id !== undefined) {
      requireUri(target.id, "id");
      body.id = target.id;
    }
    if (target.status !== undefined) {
      if (target.status !== "received") throw new TypeError("invalid status");
      body.status = target.status;
    }
    const response = await this.fetchImpl(this.baseUrl + "/receipts", {
      method: "POST",
      headers: { "Authorization": "Bearer " + this.token, "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal
    });
    if (response.status !== 202) {
      await response.body?.cancel().catch(() => {});
      throw new Error("XEIP relay rejected receipt: HTTP " + response.status);
    }
    const result: unknown = await response.json();
    const responseBody = requireRecord(result, "relay response");
    const duplicate = responseBody.duplicate;
    const seq = responseBody.seq;
    if (responseBody.acknowledged !== true || typeof responseBody.session !== "string" ||
        !Number.isSafeInteger(seq) || (seq as number) < 0 || typeof duplicate !== "boolean") {
      throw new TypeError("invalid relay response");
    }
    return { acknowledged: true, session: responseBody.session, seq: seq as number, duplicate };
  }

  /**
   * Returns the relay's events. Pass an abort signal to close the subscription
   * and an optional `after` sequence to resume within the local delivery window.
   */
  async *events(session: string, entity: string, signal?: AbortSignal, after?: number): AsyncGenerator<Envelope> {
    requireUri(session, "session");
    requireUri(entity, "entity");
    const headers: Record<string, string> = {
      "Authorization": "Bearer " + this.token, "Accept": "text/event-stream"
    };
    if (after !== undefined) {
      if (!Number.isSafeInteger(after) || after < 0) throw new TypeError("after must be a non-negative safe integer");
      headers["Last-Event-ID"] = String(after);
    }
    const url = new URL(this.baseUrl + "/events");
    url.searchParams.set("session", session);
    url.searchParams.set("entity", entity);
    const response = await this.fetchImpl(url, { headers, signal });
    if (response.status !== 200 || !response.body) {
      await response.body?.cancel().catch(() => {});
      throw new Error("XEIP event connection failed: HTTP " + response.status);
    }
    if (response.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase() !== "text/event-stream") {
      await response.body.cancel().catch(() => {});
      throw new TypeError("XEIP events require text/event-stream content type");
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    const parser = new SseParser();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        for (const frame of parser.push(decoder.decode(value, { stream: true }))) {
          if (frame.event !== "xeip.message") continue;
          const message: unknown = JSON.parse(frame.data);
          assertEnvelope(message);
          yield message;
        }
      }
    } finally {
      await reader.cancel().catch(() => {});
    }
  }
}
