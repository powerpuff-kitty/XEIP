/**
 * XEIP 0.1 development-only relay. NEVER expose it to untrusted networks.
 * Shared-token mode has no identity binding; the opt-in admission profile binds
 * locally provisioned credentials to entities. Neither mode is a production relay.
 */
import { createServer } from "node:http";
import { timingSafeEqual } from "node:crypto";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";
import { validateEnvelope, requireUri } from "../../sdks/typescript/src/validation.js";
import { LocalAdmission, LOCAL_ADMISSION_PROFILE } from "./admission.mjs";
import { ReplayWindow, LOCAL_REPLAY_PROFILE } from "./replay.mjs";
import { DeliveryLog, LOCAL_DELIVERY_PROFILE } from "./delivery.mjs";
import { DurableStore, LOCAL_DURABLE_PROFILE } from "./durable.mjs";
import { ReceiptLedger, LOCAL_RECEIPTS_PROFILE } from "./receipts.mjs";
import { LimitPolicy, LOCAL_LIMITS_PROFILE } from "./limits.mjs";
import { CLOSE, isWebSocketUpgrade, acceptWebSocket } from "./websocket.mjs";

const MAX_BODY = 64 * 1024;
const RECEIPT_FIELDS = ["session", "seq", "id", "status"];
const MAX_JSON_DEPTH = 64;
const MAX_FRAME = 128 * 1024;
const MAX_PENDING = 256 * 1024;
// Reserve room for the SSE `id:` line and the WebSocket message wrapper so the
// exact emitted frame stays within MAX_FRAME across both transports.
const FRAME_OVERHEAD = 96;

const STATUS_TEXT = {
  400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
  409: "Conflict", 413: "Payload Too Large", 415: "Unsupported Media Type",
  422: "Unprocessable Entity", 429: "Too Many Requests", 503: "Service Unavailable"
};

function refuseUpgrade(socket, status, error) {
  const body = JSON.stringify({ error });
  const response = "HTTP/1.1 " + status + " " + (STATUS_TEXT[status] ?? "Error") + "\r\n" +
    "Connection: close\r\n" +
    "Content-Type: application/json; charset=utf-8\r\n" +
    "Content-Length: " + Buffer.byteLength(body) + "\r\n\r\n" + body;
  // end() flushes the response before FIN; destroy only if the peer stalls.
  socket.end(response);
  const timer = setTimeout(() => socket.destroy(), 1000);
  timer.unref();
}
const absoluteUri = value => { try { requireUri(value); return true; } catch { return false; } };

// A write returning false still queues its bytes. Bound that queue without allowing
// one stalled client to block delivery to the rest of the session.
function writeEvent(res, frame) {
  if (res.destroyed || res.writableEnded) return false;
  if (res.writableLength + Buffer.byteLength(frame) > MAX_PENDING) {
    res.destroy();
    return false;
  }
  res.write(frame);
  return true;
}

// SSE frame for one envelope; the optional delivery sequence uses the standard
// `id:` line so clients can resume with Last-Event-ID.
function sseFrame(raw, seq) {
  return (seq === undefined ? "" : "id: " + seq + "\n") +
    "event: xeip.message\ndata: " + JSON.stringify(raw) + "\n\n";
}

// Returns undefined when absent, null when malformed, or a non-negative cursor.
function parseCursor(value) {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string" || value === "" || !/^(0|[1-9][0-9]*)$/.test(value)) return null;
  const cursor = Number(value);
  return Number.isSafeInteger(cursor) ? cursor : null;
}

function authorize(header, token) {
  if (typeof header !== "string" || !header.startsWith("Bearer ")) return false;
  const provided = Buffer.from(header.slice(7));
  const expected = Buffer.from(token);
  return provided.length === expected.length && timingSafeEqual(provided, expected);
}
function writeJson(res, status, data) {
  if (res.headersSent) return;
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  });
  res.end(JSON.stringify(data));
}
function unauthorized(res) {
  res.setHeader("WWW-Authenticate", "Bearer");
  return writeJson(res, 401, { error: "unauthorized" });
}
function validateMessage(raw) {
  try { validateEnvelope(raw); }
  catch (error) { return error.message; }
  if (raw.expiresAt !== undefined && expiryMillis(raw.expiresAt) <= Date.now()) return "message expired";
  return null;
}
function expiryMillis(timestamp) {
  // Date.parse does not accept leap seconds. Map :60 onto the following second.
  const leapSecond = timestamp.slice(17, 19) === "60";
  const normalized = timestamp.slice(0, 10) + "T" + timestamp.slice(11, 17) +
    (leapSecond ? "59" : timestamp.slice(17, 19)) + timestamp.slice(19);
  return Date.parse(normalized) + (leapSecond ? 1000 : 0);
}
async function readLimitedBody(req) {
  if (Number(req.headers["content-length"]) > MAX_BODY) throw new RangeError("body too large");
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) throw new RangeError("body too large");
    chunks.push(chunk);
  }
  return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(Buffer.concat(chunks));
}

function requireBoundedJsonDepth(value) {
  const stack = [[value, 1]];
  while (stack.length) {
    const [current, depth] = stack.pop();
    if (current === null || typeof current !== "object") continue;
    if (depth > MAX_JSON_DEPTH) throw new RangeError("JSON nesting exceeds 64 containers");
    for (const child of Object.values(current)) stack.push([child, depth + 1]);
  }
}

function loopbackOnly(req) {
  return ["127.0.0.1", "::1", "::ffff:127.0.0.1"].includes(req.socket.remoteAddress);
}

function localOrigin(req) {
  // Check the literal authority, not DNS resolution: a remote hostname may
  // resolve to loopback during rebinding. No proxy or wildcard hosts are supported.
  const host = req.headers.host;
  const match = typeof host === "string" && /^(localhost|127\.0\.0\.1|\[::1\])(?::([0-9]{1,5}))?$/i.exec(host);
  if (!match || (match[2] !== undefined && (Number(match[2]) < 1 || Number(match[2]) > 65535))) return null;
  if (req.rawHeaders.filter((header, index) => index % 2 === 0 && header.toLowerCase() === "host").length !== 1) return null;
  return new URL("http://" + host).origin;
}

/** Returns a Node HTTP server; caller must listen on 127.0.0.1 or ::1. */
export function createRelay({ token, admission, replay, delivery, durable, receipts, limits }) {
  if (admission !== undefined) {
    if (token !== undefined) throw new TypeError("choose exactly one relay authentication mode");
    if (!(admission instanceof LocalAdmission)) throw new TypeError("admission must be a LocalAdmission policy");
  } else if (typeof token !== "string" || token.length < 16) throw new Error("XEIP_DEV_TOKEN must be at least 16 characters");
  if (replay !== undefined && !admission) throw new TypeError("replay requires local admission mode");
  // `durable` backs the same delivery/resume framing as `delivery`; specify one.
  if (delivery !== undefined && durable !== undefined) {
    throw new TypeError("choose either delivery or durable, not both");
  }
  // A shared token cannot bind the acknowledging principal to a recipient, so a
  // receipt needs both authenticated admission and a retained delivery log.
  if (receipts !== undefined && (!admission || (delivery === undefined && durable === undefined))) {
    throw new TypeError("receipts require local admission and delivery");
  }
  const replayWindow = replay === undefined ? null : new ReplayWindow(replay);
  const deliveryLog = delivery === undefined ? null : new DeliveryLog(delivery);
  const durableStore = durable === undefined ? null : new DurableStore(durable);
  const store = durableStore ?? deliveryLog;
  const receiptLedger = receipts === undefined ? null : new ReceiptLedger(receipts);
  const limitPolicy = limits === undefined ? null : new LimitPolicy(limits);
  // One token-bucket decision for the current request's rate-limit key, or null
  // when the profile is disabled. The key is derived here so the policy itself
  // stays unaware of transports and principals.
  const limitDecision = (req, principal) =>
    limitPolicy === null ? null : limitPolicy.take(limitPolicy.keyFor(principal, req.socket.remoteAddress));
  // session ID -> Set of transport-neutral clients:
  // { entity, principal, alive(), write(frame, raw) -> boolean, destroy() }
  const sessions = new Map();
  const addClient = (session, client) => {
    const clients = sessions.get(session) ?? new Set();
    sessions.set(session, clients);
    clients.add(client);
  };
  const removeClient = (session, client) => {
    const clients = sessions.get(session);
    if (!clients) return;
    clients.delete(client);
    if (clients.size === 0) sessions.delete(session);
  };
  const activeCounts = entity => {
    let total = 0, entityStreams = 0;
    for (const clients of sessions.values()) for (const client of clients) {
      if (!client.alive()) continue;
      total++;
      if (client.entity === entity) entityStreams++;
    }
    return { total, entityStreams };
  };
  // Shared validation, admission, replay and routing for HTTP and WebSocket.
  // Returns an error outcome or an acceptance body; it never performs HTTP writes.
  const routeMessage = (principal, raw) => {
    const error = validateMessage(raw);
    if (error) return { status: 422, error };
    if (admission) {
      if (!admission.isCurrent(principal)) return { status: 401, error: "unauthorized" };
      if (!admission.canSend(principal, raw)) return { status: 403, error: "forbidden" };
    }
    const base = "event: xeip.message\ndata: " + JSON.stringify(raw) + "\n\n";
    // Compact numeric notation can expand when JSON is reserialized. Keep the
    // emitted bytes compatible with both reference readers before routing,
    // reserving room for the id line and WebSocket wrapper added below.
    if (Buffer.byteLength(base) > MAX_FRAME - FRAME_OVERHEAD) return { status: 413, error: "serialized SSE frame too large" };
    if (replayWindow) {
      // Record accepted scope before any write, with no asynchronous gap in routing.
      const decision = replayWindow.accept(raw);
      if (decision.status === "duplicate") return { status: 202, body: { accepted: true, delivered: 0, duplicate: true } };
      if (decision.status === "conflict") return { status: 409, error: "message ID conflict" };
      if (decision.status === "full") return { status: 503, error: "replay window full", retryAfter: decision.retryAfter };
    }
    // Assign the delivery sequence in the same synchronous step as the writes so
    // the per-session order equals acceptance order across both transports.
    const seq = store ? store.append(raw.session, raw) : undefined;
    const frame = sseFrame(raw, seq);
    let written = 0;
    for (const subscriber of sessions.get(raw.session) ?? []) {
      if (admission && !admission.canSubscribe(subscriber.principal, raw.session)) continue;
      if (raw.recipient !== undefined && subscriber.entity !== raw.recipient) continue;
      if (!subscriber.alive()) continue;
      // A write to a current stream is not a delivery acknowledgment.
      if (subscriber.write(frame, raw, seq)) written += 1;
    }
    return { status: 202, body: { accepted: true, delivered: written, ...(seq === undefined ? {} : { seq }), ...(replayWindow ? { duplicate: false } : {}) } };
  };
  // Validates a receipt control, correlates it against the retained delivery log
  // and records a bounded acknowledgment. It never writes a response and never
  // discloses message existence beyond the necessary status.
  const routeReceipt = (principal, document) => {
    if (!receiptLedger) return { status: 400, error: "receipts profile not enabled" };
    // A credential or membership can change while the asynchronous body read waits.
    if (!admission.isCurrent(principal)) return { status: 401, error: "unauthorized" };
    if (!document || typeof document !== "object" || Array.isArray(document) ||
        Object.keys(document).some(key => !RECEIPT_FIELDS.includes(key))) {
      return { status: 400, error: "invalid receipt control" };
    }
    const { session, seq, id, status } = document;
    if (!absoluteUri(session)) return { status: 400, error: "valid session URI required" };
    const hasSeq = seq !== undefined, hasId = id !== undefined;
    if (!hasSeq && !hasId) return { status: 400, error: "a seq or id selector is required" };
    if (hasSeq && (!Number.isSafeInteger(seq) || seq < 0)) return { status: 400, error: "invalid seq" };
    if (hasId && !absoluteUri(id)) return { status: 400, error: "invalid id" };
    if (status !== undefined && status !== "received") return { status: 400, error: "invalid status" };
    if (!admission.canSubscribe(principal, session)) return { status: 403, error: "forbidden" };
    // Recipient eligibility is applied BEFORE ambiguity resolution so another
    // principal's messages can never make a valid id-only receipt ambiguous.
    const eligible = candidate => candidate.message.recipient === undefined || candidate.message.recipient === principal.entity;
    let entry;
    if (hasSeq) {
      entry = store.lookup(session, seq);
      if (entry === null) return { status: 404, error: "target not retained" };
      if (hasId && entry.message.id !== id) return { status: 409, error: "selector conflict" };
      if (!eligible(entry)) return { status: 403, error: "forbidden" };
    } else {
      const matches = store.lookupAllById(session, id).filter(eligible);
      if (matches.length === 0) return { status: 404, error: "target not retained" };
      if (matches.length > 1) return { status: 409, error: "ambiguous target" };
      entry = matches[0];
    }
    const { duplicate } = receiptLedger.record(principal, session, entry.seq, entry.message.id);
    return { status: 202, body: { acknowledged: true, session, seq: entry.seq, duplicate } };
  };
  const server = createServer((req, res) => {
    // A store/disk failure must not become an unhandled rejection that kills the process.
    routeRequest(req, res).catch(() => {
      if (!res.headersSent) writeJson(res, 500, { error: "internal error" });
      else res.destroy();
    });
  });
  const routeRequest = async (req, res) => {
    // Reject non-loopback connections even if a consumer accidentally binds a public interface.
    if (!loopbackOnly(req)) return writeJson(res, 403, { error: "loopback-only development relay" });
    const origin = localOrigin(req);
    if (!origin) return writeJson(res, 403, { error: "literal loopback Host required" });
    if (req.headers.origin !== undefined && req.headers.origin !== origin) {
      return writeJson(res, 403, { error: "same-origin browser request required" });
    }
    if (!req.url?.startsWith("/") || req.url.startsWith("//")) {
      return writeJson(res, 400, { error: "origin-form request target required" });
    }
    let url;
    try {
      url = new URL(req.url, origin);
      if (url.origin !== origin) return writeJson(res, 400, { error: "request target must preserve the local origin" });
    }
    catch { return writeJson(res, 400, { error: "invalid URL" }); }
    const staticPages = {
      "/console": ["console.html", "text/html"],
      "/console.css": ["console.css", "text/css"],
      "/console.js": ["console.js", "text/javascript"]
    };
    if (req.method === "GET" && Object.hasOwn(staticPages, url.pathname)) {
      const [file, type] = staticPages[url.pathname];
      const fileContent = readFileSync(new URL("../../examples/local-relay/" + file, import.meta.url));
      res.writeHead(200, {
        "Content-Type": type + "; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
      });
      res.end(fileContent);
      return;
    }
    if (req.method === "GET" && ["/sse.js", "/validation.js"].includes(url.pathname)) {
      const content = readFileSync(new URL("../../sdks/typescript/src" + url.pathname, import.meta.url));
      res.writeHead(200, { "Content-Type": "text/javascript; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" });
      res.end(content);
      return;
    }
    if (req.method === "GET" && url.pathname === "/health") {
      const base = admission
        ? { status: "ok", protocol: "xeip/0.1", mode: "local-admission", profile: LOCAL_ADMISSION_PROFILE,
          transports: ["http-sse", "websocket"],
          ...(replayWindow ? { deliveryProfile: LOCAL_REPLAY_PROFILE, replay: replayWindow.limits } : {}) }
        : { status: "ok", protocol: "xeip/0.1", mode: "development-only", transports: ["http-sse", "websocket"] };
      if (store) {
        base.resumeProfile = LOCAL_DELIVERY_PROFILE;
        base.resume = store.resumeLimits ?? store.limits;
      }
      if (durableStore) {
        base.durableProfile = LOCAL_DURABLE_PROFILE;
        base.durable = { backend: durableStore.backend, ...durableStore.limits,
          fsync: durableStore.fsync, state: durableStore.status() };
      }
      if (receiptLedger) {
        base.receiptProfile = LOCAL_RECEIPTS_PROFILE;
        base.receipts = receiptLedger.limits;
      }
      if (limitPolicy) {
        base.limitsProfile = LOCAL_LIMITS_PROFILE;
        base.limits = limitPolicy.limits;
      }
      return writeJson(res, 200, base);
    }
    const principal = admission ? admission.authenticate(req.headers.authorization) : null;
    if (admission ? !principal : !authorize(req.headers.authorization, token)) return unauthorized(res);
    // Public health and static console assets return above and are never limited.
    if (limitPolicy) {
      const decision = limitDecision(req, principal);
      if (!decision.allowed) {
        res.setHeader("Retry-After", String(decision.retryAfter));
        return writeJson(res, 429, { error: "rate limit exceeded" });
      }
    }
    if (req.method === "GET" && url.pathname === "/events") {
      const session = url.searchParams.get("session");
      const entity = url.searchParams.get("entity");
      if (!absoluteUri(session) || !absoluteUri(entity)) return writeJson(res, 400, { error: "valid session and entity URIs required" });
      const cursorRaw = req.headers["last-event-id"] ?? url.searchParams.get("after") ?? undefined;
      const cursor = parseCursor(cursorRaw);
      if (cursor === null) return writeJson(res, 400, { error: "invalid resume cursor" });
      if (cursor !== undefined && !store) return writeJson(res, 400, { error: "delivery resume profile not enabled" });
      if (admission) {
        if (entity !== principal.entity || !admission.canSubscribe(principal, session)) return writeJson(res, 403, { error: "forbidden" });
        const { total, entityStreams } = activeCounts(principal.entity);
        if (total >= 256 || entityStreams >= 4) return writeJson(res, 429, { error: "subscription limit reached" });
      }
      // An SSE stream is a long-lived transport connection and one subscription.
      if (limitPolicy) {
        if (!limitPolicy.acquireConnection()) return writeJson(res, 429, { error: "connection limit exceeded" });
        if (!limitPolicy.acquireSubscription()) {
          limitPolicy.releaseConnection();
          return writeJson(res, 429, { error: "subscription limit exceeded" });
        }
      }
      // Only admission mode derives the stored identity from authenticated credentials.
      res.writeHead(200, {
        "Content-Type": "text/event-stream; charset=utf-8",
        "Cache-Control": "no-cache, no-transform",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",
        "X-Content-Type-Options": "nosniff"
      });
      writeEvent(res, ": connected\n\n");
      if (cursor !== undefined) {
        const { entries, gap, from } = store.since(session, cursor);
        if (gap) writeEvent(res, "event: xeip.gap\ndata: " + JSON.stringify({ session, from }) + "\n\n");
        for (const entry of entries) {
          if (entry.message.recipient !== undefined && entry.message.recipient !== entity) continue;
          if (!writeEvent(res, sseFrame(entry.message, entry.seq))) break;
        }
      }
      const client = {
        entity: admission ? principal.entity : entity,
        principal,
        alive: () => !res.destroyed && !res.writableEnded,
        write: frame => writeEvent(res, frame),
        destroy: () => res.destroy()
      };
      addClient(session, client);
      const heartbeat = setInterval(() => {
        writeEvent(res, ": heartbeat\n\n");
      }, 15000);
      heartbeat.unref();
      res.once("close", () => {
        clearInterval(heartbeat);
        removeClient(session, client);
        if (limitPolicy) {
          limitPolicy.releaseConnection();
          limitPolicy.releaseSubscription();
        }
      });
      return;
    }
    if (req.method === "POST" && url.pathname === "/messages") {
      if ((req.headers["content-type"] ?? "").split(";")[0].trim().toLowerCase() !== "application/json") {
        return writeJson(res, 415, { error: "application/json content type required" });
      }
      let raw;
      try {
        raw = JSON.parse(await readLimitedBody(req));
        requireBoundedJsonDepth(raw);
      }
      catch (err) { return writeJson(res, err instanceof RangeError ? 413 : 400, { error: "invalid or oversized JSON" }); }
      // A credential or membership can change while the asynchronous body read waits.
      const outcome = routeMessage(principal, raw);
      if (outcome.status === 401) return unauthorized(res);
      if (outcome.retryAfter !== undefined) res.setHeader("Retry-After", String(outcome.retryAfter));
      if (outcome.error !== undefined) return writeJson(res, outcome.status, { error: outcome.error });
      return writeJson(res, outcome.status, outcome.body);
    }
    if (req.method === "POST" && url.pathname === "/receipts") {
      if ((req.headers["content-type"] ?? "").split(";")[0].trim().toLowerCase() !== "application/json") {
        return writeJson(res, 415, { error: "application/json content type required" });
      }
      let document;
      try {
        document = JSON.parse(await readLimitedBody(req));
        requireBoundedJsonDepth(document);
      }
      catch (err) { return writeJson(res, err instanceof RangeError ? 413 : 400, { error: "invalid or oversized JSON" }); }
      const outcome = routeReceipt(principal, document);
      if (outcome.status === 401) return unauthorized(res);
      if (outcome.error !== undefined) return writeJson(res, outcome.status, { error: outcome.error });
      return writeJson(res, outcome.status, outcome.body);
    }
    writeJson(res, 404, { error: "route not found" });
  };
  const checkSubscriptions = () => {
    for (const [session, clients] of sessions) for (const client of clients) {
      if (!admission.canSubscribe(client.principal, session)) client.destroy();
    }
  };
  // WebSocket upgrade: same authority/browser gates and credentials as HTTP,
  // then a JSON control protocol over text frames. Envelopes are unchanged.
  server.on("upgrade", (req, socket, head) => {
    if (!loopbackOnly(req)) return refuseUpgrade(socket, 403, "loopback-only development relay");
    const origin = localOrigin(req);
    if (!origin) return refuseUpgrade(socket, 403, "literal loopback Host required");
    if (req.headers.origin !== undefined && req.headers.origin !== origin) {
      return refuseUpgrade(socket, 403, "same-origin browser request required");
    }
    let url;
    try {
      if (!req.url?.startsWith("/") || req.url.startsWith("//")) throw new Error("bad target");
      url = new URL(req.url, origin);
      if (url.origin !== origin) throw new Error("bad origin");
    } catch { return refuseUpgrade(socket, 400, "invalid URL"); }
    if (url.pathname !== "/ws") return refuseUpgrade(socket, 404, "route not found");
    if (!isWebSocketUpgrade(req)) return refuseUpgrade(socket, 400, "websocket upgrade required");
    const principal = admission ? admission.authenticate(req.headers.authorization) : null;
    if (admission ? !principal : !authorize(req.headers.authorization, token)) return refuseUpgrade(socket, 401, "unauthorized");
    if (limitPolicy) {
      const decision = limitDecision(req, principal);
      if (!decision.allowed) return refuseUpgrade(socket, 429, "rate limit exceeded");
      if (!limitPolicy.acquireConnection()) return refuseUpgrade(socket, 429, "connection limit exceeded");
    }
    const connection = acceptWebSocket(req, socket, head, { maxFrame: MAX_FRAME, maxMessage: MAX_FRAME, maxPending: MAX_PENDING });
    const ownSubscriptions = new Map(); // session -> client
    const control = value => connection.sendText(JSON.stringify(value));
    // Rate-limits one control frame; the reply is a 429 error control when denied.
    const allowControl = () => {
      const decision = limitDecision(req, principal);
      if (decision && !decision.allowed) {
        control({ type: "error", status: 429, error: "rate limit exceeded" });
        return false;
      }
      return true;
    };
    let awaitingPong = 0;
    const heartbeat = setInterval(() => {
      if (awaitingPong >= 2) return connection.close(CLOSE.tryAgain, "no pong");
      awaitingPong += 1;
      connection.ping();
    }, 15000);
    heartbeat.unref();
    connection.on("pong", () => { awaitingPong = 0; });
    connection.on("message", text => {
      try { handleControl(text); }
      catch { control({ type: "error", status: 500, error: "internal error" }); }
    });
    const handleControl = text => {
      let value;
      try { value = JSON.parse(text); }
      catch { return control({ type: "error", status: 400, error: "invalid or oversized JSON" }); }
      if (!value || typeof value !== "object" || Array.isArray(value) || typeof value.type !== "string") {
        return control({ type: "error", status: 400, error: "invalid control frame" });
      }
      if (value.type === "subscribe") {
        if (!allowControl()) return;
        const { session, entity } = value;
        if (!absoluteUri(session) || !absoluteUri(entity)) return control({ type: "error", status: 400, error: "valid session and entity URIs required" });
        let after;
        if (value.after !== undefined) {
          if (!Number.isSafeInteger(value.after) || value.after < 0) return control({ type: "error", status: 400, error: "invalid resume cursor" });
          after = value.after;
        }
        if (after !== undefined && !store) return control({ type: "error", status: 400, error: "delivery resume profile not enabled" });
        if (admission && !admission.isCurrent(principal)) {
          control({ type: "error", status: 401, error: "unauthorized" });
          return connection.close(CLOSE.policy, "revoked credential");
        }
        if (admission) {
          if (entity !== principal.entity || !admission.canSubscribe(principal, session)) return control({ type: "error", status: 403, error: "forbidden" });
          const { total, entityStreams } = activeCounts(principal.entity);
          if (total >= 256 || entityStreams >= 4) return control({ type: "error", status: 429, error: "subscription limit reached" });
        }
        const storedEntity = admission ? principal.entity : entity;
        const previous = ownSubscriptions.get(session);
        // Replacing an existing subscription keeps the same held slot; a brand
        // new subscription must fit the shared subscription cap.
        if (!previous && limitPolicy && !limitPolicy.acquireSubscription()) {
          return control({ type: "error", status: 429, error: "subscription limit exceeded" });
        }
        if (previous) { removeClient(session, previous); ownSubscriptions.delete(session); }
        const client = {
          entity: storedEntity,
          principal,
          alive: () => connection.isOpen(),
          write: (frame, raw, seq) => connection.sendText(JSON.stringify({ type: "message", ...(seq === undefined ? {} : { seq }), message: raw })),
          destroy: () => connection.close(CLOSE.policy, "authorization changed")
        };
        addClient(session, client);
        ownSubscriptions.set(session, client);
        control({ type: "subscribed", session });
        if (after !== undefined) {
          const { entries, gap, from } = store.since(session, after);
          if (gap) control({ type: "gap", session, from });
          for (const entry of entries) {
            if (entry.message.recipient !== undefined && entry.message.recipient !== storedEntity) continue;
            connection.sendText(JSON.stringify({ type: "message", seq: entry.seq, message: entry.message }));
          }
        }
        return;
      }
      if (value.type === "send") {
        if (!allowControl()) return;
        try { requireBoundedJsonDepth(value.message); }
        catch { return control({ type: "error", status: 413, error: "invalid or oversized JSON" }); }
        const outcome = routeMessage(principal, value.message);
        if (outcome.status === 401) {
          control({ type: "error", status: 401, error: "unauthorized" });
          return connection.close(CLOSE.policy, "revoked credential");
        }
        if (outcome.error !== undefined) return control({ type: "error", status: outcome.status, error: outcome.error });
        return control({ type: "accepted", delivered: outcome.body.delivered,
          ...(outcome.body.seq === undefined ? {} : { seq: outcome.body.seq }),
          ...(outcome.body.duplicate !== undefined ? { duplicate: outcome.body.duplicate } : {}) });
      }
      if (value.type === "receipt") {
        if (!allowControl()) return;
        // The `type` discriminator is transport framing, not part of the receipt.
        const document = { ...value };
        delete document.type;
        try { requireBoundedJsonDepth(document); }
        catch { return control({ type: "error", status: 413, error: "invalid or oversized JSON" }); }
        const outcome = routeReceipt(principal, document);
        if (outcome.status === 401) {
          control({ type: "error", status: 401, error: "unauthorized" });
          return connection.close(CLOSE.policy, "revoked credential");
        }
        if (outcome.error !== undefined) return control({ type: "error", status: outcome.status, error: outcome.error });
        return control({ type: "acknowledged", session: outcome.body.session, seq: outcome.body.seq, duplicate: outcome.body.duplicate });
      }
      return control({ type: "error", status: 400, error: "unknown control type" });
    };
    connection.on("close", () => {
      clearInterval(heartbeat);
      for (const [session, client] of ownSubscriptions) {
        removeClient(session, client);
        if (limitPolicy) limitPolicy.releaseSubscription();
      }
      ownSubscriptions.clear();
      if (limitPolicy) limitPolicy.releaseConnection();
    });
  });
  let stopChanges;
  server.on("listening", () => {
    stopChanges?.();
    stopChanges = admission?.onChange(checkSubscriptions);
  });
  server.on("close", () => { stopChanges?.(); stopChanges = undefined; durableStore?.close(); });
  return server;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const token = process.env.XEIP_DEV_TOKEN;
  const host = process.env.XEIP_HOST ?? "127.0.0.1";
  const port = Number(process.env.XEIP_PORT ?? "8787");
  if (!["127.0.0.1", "::1"].includes(host) || !Number.isInteger(port) || port < 1 || port > 65535) {
    console.error("XEIP development relay requires loopback host and valid port");
    process.exitCode = 1;
  } else {
    try {
      createRelay({ token }).listen(port, host, () => {
        console.log("XEIP development-only relay listening at http://" + host + ":" + port);
        console.log("Warning: shared token is NOT a verified entity identity or production authorization");
      });
    } catch (err) {
      console.error(err.message);
      process.exitCode = 1;
    }
  }
}
