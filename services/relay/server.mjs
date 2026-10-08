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
import { CLOSE, isWebSocketUpgrade, acceptWebSocket } from "./websocket.mjs";

const MAX_BODY = 64 * 1024;
const MAX_JSON_DEPTH = 64;
const MAX_FRAME = 128 * 1024;
const MAX_PENDING = 256 * 1024;

const STATUS_TEXT = {
  400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
  409: "Conflict", 413: "Payload Too Large", 415: "Unsupported Media Type",
  422: "Unprocessable Entity", 429: "Too Many Requests", 503: "Service Unavailable"
};

function refuseUpgrade(socket, status, error) {
  const body = JSON.stringify({ error });
  socket.write(
    "HTTP/1.1 " + status + " " + (STATUS_TEXT[status] ?? "Error") + "\r\n" +
    "Connection: close\r\n" +
    "Content-Type: application/json; charset=utf-8\r\n" +
    "Content-Length: " + Buffer.byteLength(body) + "\r\n\r\n" + body
  );
  socket.destroy();
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
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) return null;
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
export function createRelay({ token, admission, replay, delivery }) {
  if (admission !== undefined) {
    if (token !== undefined) throw new TypeError("choose exactly one relay authentication mode");
    if (!(admission instanceof LocalAdmission)) throw new TypeError("admission must be a LocalAdmission policy");
  } else if (typeof token !== "string" || token.length < 16) throw new Error("XEIP_DEV_TOKEN must be at least 16 characters");
  if (replay !== undefined && !admission) throw new TypeError("replay requires local admission mode");
  const replayWindow = replay === undefined ? null : new ReplayWindow(replay);
  const deliveryLog = delivery === undefined ? null : new DeliveryLog(delivery);
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
    // emitted bytes compatible with both reference readers before routing.
    if (Buffer.byteLength(base) > MAX_FRAME) return { status: 413, error: "serialized SSE frame too large" };
    if (replayWindow) {
      // Record accepted scope before any write, with no asynchronous gap in routing.
      const decision = replayWindow.accept(raw);
      if (decision.status === "duplicate") return { status: 202, body: { accepted: true, delivered: 0, duplicate: true } };
      if (decision.status === "conflict") return { status: 409, error: "message ID conflict" };
      if (decision.status === "full") return { status: 503, error: "replay window full", retryAfter: decision.retryAfter };
    }
    // Assign the delivery sequence in the same synchronous step as the writes so
    // the per-session order equals acceptance order across both transports.
    const seq = deliveryLog ? deliveryLog.append(raw.session, raw) : undefined;
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
  const server = createServer(async (req, res) => {
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
      if (deliveryLog) {
        base.resumeProfile = LOCAL_DELIVERY_PROFILE;
        base.resume = deliveryLog.limits;
      }
      return writeJson(res, 200, base);
    }
    const principal = admission ? admission.authenticate(req.headers.authorization) : null;
    if (admission ? !principal : !authorize(req.headers.authorization, token)) return unauthorized(res);
    if (req.method === "GET" && url.pathname === "/events") {
      const session = url.searchParams.get("session");
      const entity = url.searchParams.get("entity");
      if (!absoluteUri(session) || !absoluteUri(entity)) return writeJson(res, 400, { error: "valid session and entity URIs required" });
      const cursorRaw = req.headers["last-event-id"] ?? url.searchParams.get("after") ?? undefined;
      const cursor = parseCursor(cursorRaw);
      if (cursor === null) return writeJson(res, 400, { error: "invalid resume cursor" });
      if (cursor !== undefined && !deliveryLog) return writeJson(res, 400, { error: "delivery resume profile not enabled" });
      if (admission) {
        if (entity !== principal.entity || !admission.canSubscribe(principal, session)) return writeJson(res, 403, { error: "forbidden" });
        const { total, entityStreams } = activeCounts(principal.entity);
        if (total >= 256 || entityStreams >= 4) return writeJson(res, 429, { error: "subscription limit reached" });
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
        const { entries, gap, from } = deliveryLog.since(session, cursor);
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
    writeJson(res, 404, { error: "route not found" });
  });
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
    const connection = acceptWebSocket(req, socket, head, { maxFrame: MAX_FRAME, maxMessage: MAX_FRAME, maxPending: MAX_PENDING });
    const ownSubscriptions = new Map(); // session -> client
    const control = value => connection.sendText(JSON.stringify(value));
    let awaitingPong = 0;
    const heartbeat = setInterval(() => {
      if (awaitingPong >= 2) return connection.close(CLOSE.tryAgain, "no pong");
      awaitingPong += 1;
      connection.ping();
    }, 15000);
    heartbeat.unref();
    connection.on("pong", () => { awaitingPong = 0; });
    connection.on("message", text => {
      let value;
      try { value = JSON.parse(text); }
      catch { return control({ type: "error", status: 400, error: "invalid or oversized JSON" }); }
      if (!value || typeof value !== "object" || Array.isArray(value) || typeof value.type !== "string") {
        return control({ type: "error", status: 400, error: "invalid control frame" });
      }
      if (value.type === "subscribe") {
        const { session, entity } = value;
        if (!absoluteUri(session) || !absoluteUri(entity)) return control({ type: "error", status: 400, error: "valid session and entity URIs required" });
        let after;
        if (value.after !== undefined) {
          if (!Number.isSafeInteger(value.after) || value.after < 0) return control({ type: "error", status: 400, error: "invalid resume cursor" });
          after = value.after;
        }
        if (after !== undefined && !deliveryLog) return control({ type: "error", status: 400, error: "delivery resume profile not enabled" });
        if (admission) {
          if (entity !== principal.entity || !admission.canSubscribe(principal, session)) return control({ type: "error", status: 403, error: "forbidden" });
          const { total, entityStreams } = activeCounts(principal.entity);
          if (total >= 256 || entityStreams >= 4) return control({ type: "error", status: 429, error: "subscription limit reached" });
        }
        const storedEntity = admission ? principal.entity : entity;
        const previous = ownSubscriptions.get(session);
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
          const { entries, gap, from } = deliveryLog.since(session, after);
          if (gap) control({ type: "gap", session, from });
          for (const entry of entries) {
            if (entry.message.recipient !== undefined && entry.message.recipient !== storedEntity) continue;
            connection.sendText(JSON.stringify({ type: "message", seq: entry.seq, message: entry.message }));
          }
        }
        return;
      }
      if (value.type === "send") {
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
      return control({ type: "error", status: 400, error: "unknown control type" });
    });
    connection.on("close", () => {
      clearInterval(heartbeat);
      for (const [session, client] of ownSubscriptions) removeClient(session, client);
      ownSubscriptions.clear();
    });
  });
  let stopChanges;
  server.on("listening", () => {
    stopChanges?.();
    stopChanges = admission?.onChange(checkSubscriptions);
  });
  server.on("close", () => { stopChanges?.(); stopChanges = undefined; });
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
