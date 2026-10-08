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

const MAX_BODY = 64 * 1024;
const MAX_JSON_DEPTH = 64;
const MAX_FRAME = 128 * 1024;
const MAX_PENDING = 256 * 1024;
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
export function createRelay({ token, admission, replay }) {
  if (admission !== undefined) {
    if (token !== undefined) throw new TypeError("choose exactly one relay authentication mode");
    if (!(admission instanceof LocalAdmission)) throw new TypeError("admission must be a LocalAdmission policy");
  } else if (typeof token !== "string" || token.length < 16) throw new Error("XEIP_DEV_TOKEN must be at least 16 characters");
  if (replay !== undefined && !admission) throw new TypeError("replay requires local admission mode");
  const replayWindow = replay === undefined ? null : new ReplayWindow(replay);
  const sessions = new Map(); // session ID -> Set({res, entity, heartbeat})
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
      return writeJson(res, 200, admission
        ? { status: "ok", protocol: "xeip/0.1", mode: "local-admission", profile: LOCAL_ADMISSION_PROFILE,
          ...(replayWindow ? { deliveryProfile: LOCAL_REPLAY_PROFILE, replay: replayWindow.limits } : {}) }
        : { status: "ok", protocol: "xeip/0.1", mode: "development-only" });
    }
    const principal = admission ? admission.authenticate(req.headers.authorization) : null;
    if (admission ? !principal : !authorize(req.headers.authorization, token)) return unauthorized(res);
    if (req.method === "GET" && url.pathname === "/events") {
      const session = url.searchParams.get("session");
      const entity = url.searchParams.get("entity");
      if (!absoluteUri(session) || !absoluteUri(entity)) return writeJson(res, 400, { error: "valid session and entity URIs required" });
      if (admission) {
        if (entity !== principal.entity || !admission.canSubscribe(principal, session)) return writeJson(res, 403, { error: "forbidden" });
        let total = 0, entityStreams = 0;
        for (const clients of sessions.values()) for (const client of clients) {
          if (client.res.destroyed || client.res.writableEnded) continue;
          total++;
          if (client.entity === principal.entity) entityStreams++;
        }
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
      const clients = sessions.get(session) ?? new Set();
      sessions.set(session, clients);
      const subscription = { res, entity: admission ? principal.entity : entity, principal };
      clients.add(subscription);
      const heartbeat = setInterval(() => {
        writeEvent(res, ": heartbeat\n\n");
      }, 15000);
      heartbeat.unref();
      res.once("close", () => {
        clearInterval(heartbeat);
        clients.delete(subscription);
        if (clients.size === 0) sessions.delete(session);
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
      const error = validateMessage(raw);
      if (error) return writeJson(res, 422, { error });
      // A credential or membership can change while the asynchronous body read waits.
      if (admission) {
        if (!admission.isCurrent(principal)) return unauthorized(res);
        if (!admission.canSend(principal, raw)) return writeJson(res, 403, { error: "forbidden" });
      }
      let written = 0;
      const frame = "event: xeip.message\ndata: " + JSON.stringify(raw) + "\n\n";
      // Compact numeric notation can expand when JSON is reserialized. Keep
      // the emitted bytes compatible with both reference readers before routing.
      if (Buffer.byteLength(frame) > MAX_FRAME) return writeJson(res, 413, { error: "serialized SSE frame too large" });
      if (replayWindow) {
        // Record accepted scope before any write, with no asynchronous gap in routing.
        const decision = replayWindow.accept(raw);
        if (decision.status === "duplicate") return writeJson(res, 202, { accepted: true, delivered: 0, duplicate: true });
        if (decision.status === "conflict") return writeJson(res, 409, { error: "message ID conflict" });
        if (decision.status === "full") {
          res.setHeader("Retry-After", String(decision.retryAfter));
          return writeJson(res, 503, { error: "replay window full" });
        }
      }
      for (const subscriber of sessions.get(raw.session) ?? []) {
        if (admission && !admission.canSubscribe(subscriber.principal, raw.session)) continue;
        if (raw.recipient !== undefined && subscriber.entity !== raw.recipient) continue;
        if (subscriber.res.destroyed || subscriber.res.writableEnded) continue;
        // This is only a write to a current stream, NOT a delivery acknowledgment.
        if (writeEvent(subscriber.res, frame)) written += 1;
      }
      return writeJson(res, 202, { accepted: true, delivered: written, ...(replayWindow ? { duplicate: false } : {}) });
    }
    writeJson(res, 404, { error: "route not found" });
  });
  const checkSubscriptions = () => {
    for (const [session, clients] of sessions) for (const client of clients) {
      if (!admission.canSubscribe(client.principal, session)) client.res.destroy();
    }
  };
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
