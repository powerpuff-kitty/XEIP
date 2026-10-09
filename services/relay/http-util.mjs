/**
 * Pure, stateless transport helpers shared by the HTTP and WebSocket relay
 * surfaces. Nothing here closes over per-server state; the functions only touch
 * their arguments. `req`/`res`/`socket` adaptation lives here, never in the
 * transport-agnostic core.
 */
import { timingSafeEqual } from "node:crypto";
import { validateEnvelope, requireUri } from "../../sdks/typescript/src/validation.js";

export const MAX_BODY = 64 * 1024;
export const MAX_JSON_DEPTH = 64;
export const MAX_FRAME = 128 * 1024;
export const MAX_PENDING = 256 * 1024;

export const STATUS_TEXT = {
  400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
  409: "Conflict", 413: "Payload Too Large", 415: "Unsupported Media Type",
  422: "Unprocessable Entity", 429: "Too Many Requests", 503: "Service Unavailable"
};

export function refuseUpgrade(socket, status, error) {
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
export const absoluteUri = value => { try { requireUri(value); return true; } catch { return false; } };

// A write returning false still queues its bytes. Bound that queue without allowing
// one stalled client to block delivery to the rest of the session.
export function writeEvent(res, frame) {
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
export function sseFrame(raw, seq) {
  return (seq === undefined ? "" : "id: " + seq + "\n") +
    "event: xeip.message\ndata: " + JSON.stringify(raw) + "\n\n";
}

// Returns undefined when absent, null when malformed, or a non-negative cursor.
export function parseCursor(value) {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string" || value === "" || !/^(0|[1-9][0-9]*)$/.test(value)) return null;
  const cursor = Number(value);
  return Number.isSafeInteger(cursor) ? cursor : null;
}

export function authorize(header, token) {
  if (typeof header !== "string" || !header.startsWith("Bearer ")) return false;
  const provided = Buffer.from(header.slice(7));
  const expected = Buffer.from(token);
  return provided.length === expected.length && timingSafeEqual(provided, expected);
}
export function writeJson(res, status, data) {
  if (res.headersSent) return;
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  });
  res.end(JSON.stringify(data));
}
export function unauthorized(res) {
  res.setHeader("WWW-Authenticate", "Bearer");
  return writeJson(res, 401, { error: "unauthorized" });
}
export function validateMessage(raw) {
  try { validateEnvelope(raw); }
  catch (error) { return error.message; }
  if (raw.expiresAt !== undefined && expiryMillis(raw.expiresAt) <= Date.now()) return "message expired";
  return null;
}
export function expiryMillis(timestamp) {
  // Date.parse does not accept leap seconds. Map :60 onto the following second.
  const leapSecond = timestamp.slice(17, 19) === "60";
  const normalized = timestamp.slice(0, 10) + "T" + timestamp.slice(11, 17) +
    (leapSecond ? "59" : timestamp.slice(17, 19)) + timestamp.slice(19);
  return Date.parse(normalized) + (leapSecond ? 1000 : 0);
}
export async function readLimitedBody(req) {
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

export function requireBoundedJsonDepth(value) {
  const stack = [[value, 1]];
  while (stack.length) {
    const [current, depth] = stack.pop();
    if (current === null || typeof current !== "object") continue;
    if (depth > MAX_JSON_DEPTH) throw new RangeError("JSON nesting exceeds 64 containers");
    for (const child of Object.values(current)) stack.push([child, depth + 1]);
  }
}

export function loopbackOnly(req) {
  return ["127.0.0.1", "::1", "::ffff:127.0.0.1"].includes(req.socket.remoteAddress);
}

export function localOrigin(req) {
  // Check the literal authority, not DNS resolution: a remote hostname may
  // resolve to loopback during rebinding. No proxy or wildcard hosts are supported.
  const host = req.headers.host;
  const match = typeof host === "string" && /^(localhost|127\.0\.0\.1|\[::1\])(?::([0-9]{1,5}))?$/i.exec(host);
  if (!match || (match[2] !== undefined && (Number(match[2]) < 1 || Number(match[2]) > 65535))) return null;
  if (req.rawHeaders.filter((header, index) => index % 2 === 0 && header.toLowerCase() === "host").length !== 1) return null;
  return new URL("http://" + host).origin;
}
