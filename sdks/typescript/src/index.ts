/**
 * Experimental XEIP v0.1 TypeScript reference SDK.
 * Validation is structural only; sender strings are not verified identities.
 */
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
function requireString(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || value.length === 0) throw new TypeError(label + " must be nonempty string");
}
function requireUri(value: unknown, label: string): asserts value is string {
  requireString(value, label);
  try {
    const uri = new URL(value);
    if (!uri.protocol || uri.protocol === ":") throw new Error("invalid scheme");
  } catch {
    throw new TypeError(label + " must be absolute URI");
  }
}
function requireUtc(value: unknown, label: string): asserts value is string {
  requireString(value, label);
  if (!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$/.test(value) ||
      Number.isNaN(Date.parse(value))) {
    throw new TypeError(label + " must be UTC RFC3339 date-time");
  }
}
function checkFields(value: Record<string, unknown>, allowed: readonly string[]): void {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) throw new TypeError("unexpected field: " + key);
  }
}
function requireVersion(value: unknown): void {
  if (value !== XEIP_VERSION) throw new TypeError("unsupported XEIP version");
}

export function assertEnvelope(value: unknown): asserts value is Envelope {
  const e = requireRecord(value, "envelope");
  checkFields(e, ["xeip", "id", "kind", "sender", "recipient", "session", "timestamp", "body", "replyTo", "expiresAt", "extensions"]);
  requireVersion(e.xeip);
  requireUri(e.id, "id");
  if (!["message", "event", "command", "receipt"].includes(String(e.kind))) throw new TypeError("unknown kind");
  requireUri(e.sender, "sender");
  requireUri(e.session, "session");
  if (e.recipient !== undefined) requireUri(e.recipient, "recipient");
  if (e.replyTo !== undefined) requireUri(e.replyTo, "replyTo");
  requireUtc(e.timestamp, "timestamp");
  if (e.expiresAt !== undefined) requireUtc(e.expiresAt, "expiresAt");
  const body = requireRecord(e.body, "body");
  checkFields(body, ["contentType", "data"]);
  requireString(body.contentType, "body.contentType");
  if (!Object.hasOwn(body, "data")) throw new TypeError("body.data missing");
  if (e.extensions !== undefined) requireRecord(e.extensions, "extensions");
}

export function assertEntity(value: unknown): asserts value is Entity {
  const e = requireRecord(value, "entity");
  checkFields(e, ["xeip", "id", "name", "kinds", "endpoints", "capabilities", "extensions"]);
  requireVersion(e.xeip);
  requireUri(e.id, "id");
  if (e.name !== undefined) requireString(e.name, "name");
  if (!Array.isArray(e.kinds) || e.kinds.length === 0 ||
      e.kinds.some(k => !["human", "agent", "machine", "service"].includes(k)) ||
      new Set(e.kinds).size !== e.kinds.length) throw new TypeError("invalid entity kinds");
  if (e.endpoints !== undefined) {
    if (!Array.isArray(e.endpoints)) throw new TypeError("endpoints must be array");
    for (const raw of e.endpoints) {
      const endpoint = requireRecord(raw, "endpoint");
      checkFields(endpoint, ["transport", "url"]);
      if (!["http-sse", "http", "websocket", "local", "webrtc", "a2a", "mcp"].includes(String(endpoint.transport))) throw new TypeError("invalid endpoint transport");
      requireUri(endpoint.url, "endpoint.url");
    }
  }
  if (e.capabilities !== undefined) {
    if (!Array.isArray(e.capabilities)) throw new TypeError("capabilities must be array");
    for (const raw of e.capabilities) {
      const cap = requireRecord(raw, "capability");
      checkFields(cap, ["id", "description", "spec"]);
      requireString(cap.id, "capability.id");
      if (!/^[a-z][a-z0-9]*(?:[.:-][a-z0-9-]+)*$/.test(cap.id)) throw new TypeError("invalid capability id");
      if (cap.description !== undefined && typeof cap.description !== "string") throw new TypeError("invalid capability description");
      if (cap.spec !== undefined) requireUri(cap.spec, "capability.spec");
    }
  }
  if (e.extensions !== undefined) requireRecord(e.extensions, "extensions");
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

  async send(message: Envelope): Promise<{ accepted: boolean; delivered: number }> {
    assertEnvelope(message);
    const response = await this.fetchImpl(this.baseUrl + "/messages", {
      method: "POST",
      headers: { "Authorization": "Bearer " + this.token, "Content-Type": "application/json" },
      body: JSON.stringify(message)
    });
    if (!response.ok) throw new Error("XEIP relay rejected message: HTTP " + response.status);
    const result: unknown = await response.json();
    const responseBody = requireRecord(result, "relay response");
    if (responseBody.accepted !== true || typeof responseBody.delivered !== "number") throw new TypeError("invalid relay response");
    return { accepted: true, delivered: responseBody.delivered };
  }

  /** Returns the relay's events; caller owns the abort signal to close the stream. */
  async *events(session: string, entity: string, signal?: AbortSignal): AsyncGenerator<Envelope> {
    requireUri(session, "session");
    requireUri(entity, "entity");
    const url = new URL(this.baseUrl + "/events");
    url.searchParams.set("session", session);
    url.searchParams.set("entity", entity);
    const response = await this.fetchImpl(url, {
      headers: { "Authorization": "Bearer " + this.token, "Accept": "text/event-stream" },
      signal
    });
    if (!response.ok || !response.body) throw new Error("XEIP event connection failed: HTTP " + response.status);
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true }).replace(/\r\n/g, "\n");
        // Event records are separated by a blank line.
        let boundary: number;
        while ((boundary = buffer.indexOf("\n\n")) >= 0) {
          const frame = buffer.slice(0, boundary);
          buffer = buffer.slice(boundary + 2);
          let event = "";
          const data: string[] = [];
          for (const line of frame.split("\n")) {
            if (line.startsWith("event:")) event = line.slice(6).trim();
            if (line.startsWith("data:")) data.push(line.slice(5).trimStart());
          }
          if (event !== "xeip.message" || data.length === 0) continue;
          const message: unknown = JSON.parse(data.join("\n"));
          assertEnvelope(message);
          yield message;
        }
      }
    } finally {
      await reader.cancel().catch(() => {});
    }
  }
}
