/**
 * XEIP 0.1 development-only relay. NEVER expose it to untrusted networks.
 * One shared demo token authenticates all connections, but does not bind entity identities.
 */
import { createServer } from "node:http";
import { timingSafeEqual } from "node:crypto";
import { fileURLToPath } from "node:url";

const MAX_BODY = 64 * 1024;
const allowedKinds = new Set(["message", "event", "command", "receipt"]);
const absoluteUri = value => typeof value === "string" &&
  /^[a-z][a-z0-9+.-]*:[^\s]+$/i.test(value);
const utcTime = value => typeof value === "string" &&
  /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$/.test(value) &&
  Number.isFinite(Date.parse(value));
const isRecord = value => value !== null && typeof value === "object" && !Array.isArray(value);

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
function validateMessage(raw) {
  if (!isRecord(raw)) return "message must be object";
  const allowed = new Set(["xeip", "id", "kind", "sender", "recipient", "session", "timestamp", "body", "replyTo", "expiresAt", "extensions"]);
  if (Object.keys(raw).some(k => !allowed.has(k))) return "unrecognized envelope field";
  if (raw.xeip !== "0.1") return "unsupported XEIP version";
  if (!absoluteUri(raw.id) || !absoluteUri(raw.sender) || !absoluteUri(raw.session)) return "invalid message, sender or session URI";
  if (raw.recipient !== undefined && !absoluteUri(raw.recipient)) return "invalid recipient URI";
  if (raw.replyTo !== undefined && !absoluteUri(raw.replyTo)) return "invalid replyTo URI";
  if (!allowedKinds.has(raw.kind)) return "invalid message kind";
  if (!utcTime(raw.timestamp)) return "invalid timestamp";
  if (!isRecord(raw.body) || typeof raw.body.contentType !== "string" || !raw.body.contentType.trim() ||
      !Object.hasOwn(raw.body, "data") || Object.keys(raw.body).some(k => !["contentType", "data"].includes(k)))
    return "invalid message body";
  if (raw.extensions !== undefined && !isRecord(raw.extensions)) return "invalid extensions";
  if (raw.expiresAt !== undefined) {
    if (!utcTime(raw.expiresAt)) return "invalid expiresAt";
    if (Date.parse(raw.expiresAt) <= Date.now()) return "message expired";
  }
  return null;
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
  return Buffer.concat(chunks).toString("utf8");
}

function loopbackOnly(req) {
  return ["127.0.0.1", "::1", "::ffff:127.0.0.1"].includes(req.socket.remoteAddress);
}

/** Returns a Node HTTP server; caller must listen on 127.0.0.1 or ::1. */
export function createRelay({ token }) {
  if (typeof token !== "string" || token.length < 16) throw new Error("XEIP_DEV_TOKEN must be at least 16 characters");
  const sessions = new Map(); // session ID -> Set({res, entity, heartbeat})
  const server = createServer(async (req, res) => {
    // Reject non-loopback connections even if a consumer accidentally binds a public interface.
    if (!loopbackOnly(req)) return writeJson(res, 403, { error: "loopback-only development relay" });
    let url;
    try { url = new URL(req.url ?? "/", "http://localhost"); }
    catch { return writeJson(res, 400, { error: "invalid URL" }); }
    if (req.method === "GET" && url.pathname === "/health") {
      return writeJson(res, 200, { status: "ok", protocol: "xeip/0.1", mode: "development-only" });
    }
    if (!authorize(req.headers.authorization, token)) {
      res.setHeader("WWW-Authenticate", "Bearer");
      return writeJson(res, 401, { error: "unauthorized" });
    }
    if (req.method === "GET" && url.pathname === "/events") {
      const session = url.searchParams.get("session");
      const entity = url.searchParams.get("entity");
      if (!absoluteUri(session) || !absoluteUri(entity)) return writeJson(res, 400, { error: "valid session and entity URIs required" });
      // Entity strings are client-supplied selectors, NOT authenticated identities.
      res.writeHead(200, {
        "Content-Type": "text/event-stream; charset=utf-8",
        "Cache-Control": "no-cache, no-transform",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",
        "X-Content-Type-Options": "nosniff"
      });
      res.write(": connected\n\n");
      const clients = sessions.get(session) ?? new Set();
      sessions.set(session, clients);
      const subscription = { res, entity };
      clients.add(subscription);
      const heartbeat = setInterval(() => {
        if (!res.destroyed) res.write(": heartbeat\n\n");
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
      if (!(req.headers["content-type"] ?? "").startsWith("application/json")) {
        return writeJson(res, 415, { error: "application/json content type required" });
      }
      let raw;
      try { raw = JSON.parse(await readLimitedBody(req)); }
      catch (err) { return writeJson(res, err instanceof RangeError ? 413 : 400, { error: "invalid or oversized JSON" }); }
      const error = validateMessage(raw);
      if (error) return writeJson(res, 422, { error });
      let written = 0;
      for (const subscriber of sessions.get(raw.session) ?? []) {
        if (raw.recipient !== undefined && subscriber.entity !== raw.recipient) continue;
        if (subscriber.res.destroyed || subscriber.res.writableEnded) continue;
        // This is only a write to a current stream, NOT a delivery acknowledgment.
        subscriber.res.write("event: xeip.message\ndata: " + JSON.stringify(raw) + "\n\n");
        written += 1;
      }
      return writeJson(res, 202, { accepted: true, delivered: written });
    }
    writeJson(res, 404, { error: "route not found" });
  });
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
