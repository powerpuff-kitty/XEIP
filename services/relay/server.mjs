/**
 * XEIP 0.1 development-only relay. NEVER expose it to untrusted networks.
 * Shared-token mode has no identity binding; the opt-in admission profile binds
 * locally provisioned credentials to entities. The opt-in `signatures` profile
 * additionally requires a detached Ed25519 signature bound to `sender`; it
 * combines with either authentication mode. No mode is a production relay.
 */
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";
import { createRelayCore } from "./relay-core.mjs";
import {
  refuseUpgrade, writeJson, unauthorized, writeEvent, sseFrame, parseCursor,
  readLimitedBody, requireBoundedJsonDepth, loopbackOnly, localOrigin,
  MAX_FRAME, MAX_PENDING
} from "./http-util.mjs";
import { openSubscription } from "./subscription.mjs";
import { CLOSE, isWebSocketUpgrade, acceptWebSocket } from "./websocket.mjs";

/** Returns a Node HTTP server; caller must listen on 127.0.0.1 or ::1. */
export function createRelay({ token, admission, replay, delivery, durable, receipts, limits, signatures }) {
  const core = createRelayCore({ token, admission, replay, delivery, durable, receipts, limits, signatures });
  const { limitPolicy, durableStore } = core;
  const limitDecision = (req, principal) => core.limitDecision(principal, req.socket.remoteAddress);
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
      return writeJson(res, 200, core.health());
    }
    const principal = core.authenticate(req.headers.authorization);
    if (!principal) return unauthorized(res);
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
      const cursorRaw = req.headers["last-event-id"] ?? url.searchParams.get("after") ?? undefined;
      const client = {
        principal,
        alive: () => !res.destroyed && !res.writableEnded,
        write: frame => writeEvent(res, frame),
        destroy: () => res.destroy()
      };
      const opened = openSubscription(core, {
        principal, session, entity, client,
        readAfter: () => {
          const cursor = parseCursor(cursorRaw);
          return cursor === null ? { error: { status: 400, error: "invalid resume cursor" } } : { after: cursor };
        },
        // An SSE stream is a long-lived transport connection and one subscription.
        reserve: () => {
          if (!limitPolicy) return null;
          return limitPolicy.acquireConnection() ? null : { status: 429, error: "connection limit exceeded" };
        },
        release: () => { if (limitPolicy) limitPolicy.releaseConnection(); }
      });
      if (opened.error) return writeJson(res, opened.error.status, { error: opened.error.error });
      res.writeHead(200, {
        "Content-Type": "text/event-stream; charset=utf-8",
        "Cache-Control": "no-cache, no-transform",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",
        "X-Content-Type-Options": "nosniff"
      });
      writeEvent(res, ": connected\n\n");
      if (opened.resume) {
        if (opened.resume.gap) writeEvent(res, "event: xeip.gap\ndata: " + JSON.stringify({ session, from: opened.resume.from }) + "\n\n");
        for (const entry of opened.resume.backlog) {
          if (!writeEvent(res, sseFrame(entry.message, entry.seq))) break;
        }
      }
      const heartbeat = setInterval(() => {
        writeEvent(res, ": heartbeat\n\n");
      }, 15000);
      heartbeat.unref();
      res.once("close", () => {
        clearInterval(heartbeat);
        opened.close();
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
      const outcome = core.routeMessage(principal, raw);
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
      const outcome = core.routeReceipt(principal, document);
      if (outcome.status === 401) return unauthorized(res);
      if (outcome.error !== undefined) return writeJson(res, outcome.status, { error: outcome.error });
      return writeJson(res, outcome.status, outcome.body);
    }
    writeJson(res, 404, { error: "route not found" });
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
    const principal = core.authenticate(req.headers.authorization);
    if (!principal) return refuseUpgrade(socket, 401, "unauthorized");
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
        const client = {
          principal,
          alive: () => connection.isOpen(),
          write: (frame, raw, seq) => connection.sendText(JSON.stringify({ type: "message", ...(seq === undefined ? {} : { seq }), message: raw })),
          destroy: () => connection.close(CLOSE.policy, "authorization changed")
        };
        const opened = openSubscription(core, {
          principal, session, entity, client,
          previous: ownSubscriptions.get(session)?.client,
          recheckCurrent: true,
          readAfter: () => {
            if (value.after === undefined) return { after: undefined };
            if (!Number.isSafeInteger(value.after) || value.after < 0) return { error: { status: 400, error: "invalid resume cursor" } };
            return { after: value.after };
          }
        });
        if (opened.error) {
          control({ type: "error", status: opened.error.status, error: opened.error.error });
          if (opened.terminate) connection.close(CLOSE.policy, "revoked credential");
          return;
        }
        ownSubscriptions.set(session, opened);
        control({ type: "subscribed", session });
        if (opened.resume) {
          if (opened.resume.gap) control({ type: "gap", session, from: opened.resume.from });
          for (const entry of opened.resume.backlog) {
            connection.sendText(JSON.stringify({ type: "message", seq: entry.seq, message: entry.message }));
          }
        }
        return;
      }
      if (value.type === "send") {
        if (!allowControl()) return;
        try { requireBoundedJsonDepth(value.message); }
        catch { return control({ type: "error", status: 413, error: "invalid or oversized JSON" }); }
        const outcome = core.routeMessage(principal, value.message);
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
        const outcome = core.routeReceipt(principal, document);
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
      for (const opened of ownSubscriptions.values()) opened.close();
      ownSubscriptions.clear();
      if (limitPolicy) limitPolicy.releaseConnection();
    });
  });
  let stopChanges;
  server.on("listening", () => {
    stopChanges?.();
    stopChanges = admission?.onChange(core.checkSubscriptions);
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
