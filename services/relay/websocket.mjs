/**
 * Minimal dependency-free RFC 6455 WebSocket support for the XEIP development
 * relay. It implements only the server role over a raw upgraded socket:
 * masked client frames, text messages, control frames, fragmentation and
 * bounded outbound buffering. It is a local demonstrator, not a production
 * WebSocket stack.
 */
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";

const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_CONTROL_PAYLOAD = 125;

export const OPCODES = Object.freeze({
  continuation: 0x0,
  text: 0x1,
  binary: 0x2,
  close: 0x8,
  ping: 0x9,
  pong: 0xa
});

export const CLOSE = Object.freeze({
  normal: 1000,
  protocol: 1002,
  unsupported: 1003,
  invalidPayload: 1007,
  policy: 1008,
  tooBig: 1009,
  tryAgain: 1013
});

export class WebSocketError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

// Close codes a peer may send: the RFC 6455 range minus reserved codes, plus
// the registered/private application ranges. 1005/1006/1015 must never appear
// on the wire.
function isValidCloseCode(code) {
  if (code >= 3000 && code <= 4999) return true;
  if (code < 1000 || code > 1014) return false;
  return code !== 1004 && code !== 1005 && code !== 1006;
}

export function websocketAccept(key) {
  return createHash("sha1").update(key + GUID).digest("base64");
}

function isValidKey(key) {
  if (typeof key !== "string") return false;
  const decoded = Buffer.from(key, "base64");
  return decoded.length === 16 && decoded.toString("base64") === key;
}

/** True when the request is a well-formed WebSocket upgrade for version 13. */
export function isWebSocketUpgrade(req) {
  const connection = req.headers.connection;
  return req.method === "GET" &&
    (req.headers.upgrade ?? "").toLowerCase() === "websocket" &&
    typeof connection === "string" && connection.toLowerCase().split(/\s*,\s*/).includes("upgrade") &&
    req.headers["sec-websocket-version"] === "13" &&
    isValidKey(req.headers["sec-websocket-key"]);
}

export function encodeFrame(opcode, payload, fin = true, maskKey = null) {
  const length = payload.length;
  let header;
  if (length <= 125) {
    header = Buffer.alloc(2);
    header[1] = length;
  } else if (length <= 0xffff) {
    header = Buffer.alloc(4);
    header[1] = 126;
    header.writeUInt16BE(length, 2);
  } else {
    header = Buffer.alloc(10);
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(length), 2);
  }
  header[0] = (fin ? 0x80 : 0x00) | opcode;
  if (!maskKey) return Buffer.concat([header, payload]);
  header[1] |= 0x80;
  const masked = Buffer.allocUnsafe(length);
  for (let i = 0; i < length; i++) masked[i] = payload[i] ^ maskKey[i & 3];
  return Buffer.concat([header, maskKey, masked]);
}

/**
 * Incremental server-side frame reader. Client frames must be masked. Text
 * messages are reassembled across fragments and validated as UTF-8.
 */
export class FrameParser {
  // Incoming bytes are held as a list of chunks with a read offset rather than a
  // single re-concatenated buffer, so a large frame delivered in many tiny TCP
  // segments costs O(frame) instead of O(frame^2) memcpy.
  #chunks = [];
  #offset = 0;
  #length = 0;
  #fragmentOpcode = null;
  #fragments = [];
  #fragmentLength = 0;
  #fragmentCount = 0;

  constructor({ maxFrame, maxMessage, maxFragments = 1024, expectMask = true }) {
    this.maxFrame = maxFrame;
    this.maxMessage = maxMessage;
    this.maxFragments = maxFragments;
    this.expectMask = expectMask;
  }

  push(chunk) {
    if (chunk.length > 0) { this.#chunks.push(chunk); this.#length += chunk.length; }
    const events = [];
    for (;;) {
      const frame = this.#readFrame();
      if (!frame) break;
      this.#handleFrame(frame, events);
    }
    return events;
  }

  // Byte at a relative offset from the read cursor, or -1 when unavailable.
  #peek(relative) {
    if (relative < 0 || relative >= this.#length) return -1;
    let remaining = relative;
    for (let index = 0; index < this.#chunks.length; index++) {
      const chunk = this.#chunks[index];
      const start = index === 0 ? this.#offset : 0;
      const available = chunk.length - start;
      if (remaining < available) return chunk[start + remaining];
      remaining -= available;
    }
    return -1;
  }

  // Consume exactly `count` bytes (already known available) in one pass.
  #take(count) {
    const out = Buffer.allocUnsafe(count);
    let written = 0;
    while (written < count) {
      const chunk = this.#chunks[0];
      const available = chunk.length - this.#offset;
      const need = count - written;
      if (need >= available) {
        chunk.copy(out, written, this.#offset);
        written += available;
        this.#chunks.shift();
        this.#offset = 0;
      } else {
        chunk.copy(out, written, this.#offset, this.#offset + need);
        this.#offset += need;
        written += need;
      }
    }
    this.#length -= count;
    return out;
  }

  #readFrame() {
    if (this.#length < 2) return null;
    const first = this.#peek(0);
    const second = this.#peek(1);
    const fin = (first & 0x80) !== 0;
    const rsv = first & 0x70;
    const opcode = first & 0x0f;
    const masked = (second & 0x80) !== 0;
    let length = second & 0x7f;
    let headerLength = 2;
    if (rsv !== 0) throw new WebSocketError(CLOSE.protocol, "reserved bits set");
    if (length === 126) {
      if (this.#length < 4) return null;
      length = (this.#peek(2) << 8) | this.#peek(3);
      headerLength = 4;
      if (length < 126) throw new WebSocketError(CLOSE.protocol, "non-minimal length encoding");
    } else if (length === 127) {
      if (this.#length < 10) return null;
      if ((this.#peek(2) & 0x80) !== 0) throw new WebSocketError(CLOSE.protocol, "invalid 64-bit length");
      let wide = 0n;
      for (let index = 0; index < 8; index++) wide = (wide << 8n) | BigInt(this.#peek(2 + index));
      length = Number(wide);
      headerLength = 10;
      if (length <= 0xffff) throw new WebSocketError(CLOSE.protocol, "non-minimal length encoding");
      if (wide > BigInt(Number.MAX_SAFE_INTEGER)) throw new WebSocketError(CLOSE.tooBig, "frame exceeds supported size");
    }
    const isControl = opcode >= 0x8;
    if (isControl && (length > MAX_CONTROL_PAYLOAD || !fin)) throw new WebSocketError(CLOSE.protocol, "invalid control frame");
    if (!isControl && length > this.maxFrame) throw new WebSocketError(CLOSE.tooBig, "frame exceeds limit");
    if (masked !== this.expectMask) throw new WebSocketError(CLOSE.protocol, this.expectMask ? "client frames must be masked" : "server frames must not be masked");
    const maskOffset = headerLength;
    const payloadOffset = headerLength + (this.expectMask ? 4 : 0);
    const total = payloadOffset + length;
    if (this.#length < total) return null;
    const frame = this.#take(total);
    let payload = frame.subarray(payloadOffset);
    if (this.expectMask) {
      const mask = frame.subarray(maskOffset, maskOffset + 4);
      const unmasked = Buffer.allocUnsafe(length);
      for (let index = 0; index < length; index++) unmasked[index] = payload[index] ^ mask[index & 3];
      payload = unmasked;
    }
    return { fin, opcode, payload };
  }

  #handleFrame({ fin, opcode, payload }, events) {
    if (opcode === OPCODES.close) {
      if (payload.length === 1) throw new WebSocketError(CLOSE.protocol, "invalid close payload");
      if (payload.length === 0) return events.push({ type: "close", code: CLOSE.normal, reason: "" });
      const code = payload.readUInt16BE(0);
      if (!isValidCloseCode(code)) throw new WebSocketError(CLOSE.protocol, "invalid close code");
      let reason;
      try {
        reason = new TextDecoder("utf-8", { fatal: true }).decode(payload.subarray(2));
      } catch {
        throw new WebSocketError(CLOSE.invalidPayload, "invalid close reason");
      }
      events.push({ type: "close", code, reason });
      return;
    }
    if (opcode === OPCODES.ping) return events.push({ type: "ping", payload });
    if (opcode === OPCODES.pong) return events.push({ type: "pong", payload });
    if (opcode === OPCODES.binary) throw new WebSocketError(CLOSE.unsupported, "binary messages are not supported");
    if (opcode === OPCODES.continuation) {
      if (this.#fragmentOpcode === null) throw new WebSocketError(CLOSE.protocol, "unexpected continuation frame");
    } else if (opcode === OPCODES.text) {
      if (this.#fragmentOpcode !== null) throw new WebSocketError(CLOSE.protocol, "nested fragmented message");
      this.#fragmentOpcode = opcode;
    } else {
      throw new WebSocketError(CLOSE.protocol, "unknown opcode");
    }
    this.#fragmentLength += payload.length;
    if (this.#fragmentLength > this.maxMessage) throw new WebSocketError(CLOSE.tooBig, "message exceeds limit");
    // Bound the number of fragments too: zero-length continuations cost ~2 wire
    // bytes each, so a count bound prevents unbounded allocation.
    if (++this.#fragmentCount > this.maxFragments) throw new WebSocketError(CLOSE.tooBig, "too many fragments");
    this.#fragments.push(payload);
    if (!fin) return;
    const bytes = Buffer.concat(this.#fragments);
    this.#fragments = [];
    this.#fragmentOpcode = null;
    this.#fragmentLength = 0;
    this.#fragmentCount = 0;
    let text;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      throw new WebSocketError(CLOSE.invalidPayload, "invalid UTF-8 text message");
    }
    events.push({ type: "message", text });
  }
}

export class WebSocketConnection extends EventEmitter {
  #socket;
  #parser;
  #closed = false;
  #closeSent = false;
  #closeTimer = null;

  constructor(socket, head = Buffer.alloc(0), { maxFrame = 128 * 1024, maxMessage = 128 * 1024, maxPending = 256 * 1024 } = {}) {
    super();
    this.#socket = socket;
    this.maxPending = maxPending;
    this.#parser = new FrameParser({ maxFrame, maxMessage });
    socket.setNoDelay(true);
    socket.on("data", chunk => this.#feed(chunk));
    socket.on("error", () => this.#finalize());
    socket.on("close", () => this.#finalize());
    // The upgraded socket is half-open: a peer FIN does not close our side, so
    // without this the server can never finish closing. Complete the close.
    socket.on("end", () => this.#socket.end());
    if (head.length > 0) this.#feed(head);
  }

  isOpen() {
    return !this.#closed && !this.#closeSent && !this.#socket.destroyed;
  }

  sendText(text) {
    if (!this.isOpen()) return false;
    // A false socket.write only means the bytes were queued, not that they
    // failed, so count the frame as delivered once it is within the bound.
    return this.#enqueue(encodeFrame(OPCODES.text, Buffer.from(text, "utf8")));
  }

  ping(payload = Buffer.alloc(0)) {
    if (this.isOpen()) this.#enqueue(encodeFrame(OPCODES.ping, payload));
  }

  // Bounded outbound write for every frame except the final close frame. A peer
  // that never reads must not be able to grow the socket buffer without limit
  // (ping/pong/close included), so all data and heartbeat frames go through here.
  #enqueue(frame) {
    if (!this.isOpen()) return false;
    if (this.#socket.writableLength + frame.length > this.maxPending) {
      this.close(CLOSE.tryAgain, "outbound queue full");
      return false;
    }
    this.#write(frame);
    return true;
  }

  close(code = CLOSE.normal, reason = "") {
    if (this.#closed) return;
    if (!this.#closeSent) {
      this.#closeSent = true;
      const reasonBytes = Buffer.from(reason, "utf8").subarray(0, MAX_CONTROL_PAYLOAD - 2);
      const body = Buffer.alloc(2 + reasonBytes.length);
      body.writeUInt16BE(code, 0);
      reasonBytes.copy(body, 2);
      this.#write(encodeFrame(OPCODES.close, body));
    }
    this.#socket.end();
    // The upgraded socket is half-open: if the peer keeps its side open after
    // our FIN, force cleanup so heartbeat/streams/server.close() do not hang.
    if (this.#closeTimer === null) {
      this.#closeTimer = setTimeout(() => this.#socket.destroy(), 1000);
      this.#closeTimer.unref();
    }
  }

  destroy() {
    this.#socket.destroy();
  }

  #feed(chunk) {
    if (this.#closed) return;
    let events;
    try {
      events = this.#parser.push(chunk);
    } catch (error) {
      this.close(error instanceof WebSocketError ? error.code : CLOSE.protocol, error.message ?? "protocol error");
      return;
    }
    for (const event of events) {
      if (this.#closed) return;
      if (event.type === "message") this.emit("message", event.text);
      else if (event.type === "ping") this.#enqueue(encodeFrame(OPCODES.pong, event.payload));
      else if (event.type === "pong") this.emit("pong", event.payload);
      else if (event.type === "close") { this.close(event.code, event.reason); return; }
    }
  }

  #write(frame) {
    try {
      return this.#socket.write(frame);
    } catch {
      this.#finalize();
      return false;
    }
  }

  #finalize() {
    if (this.#closed) return;
    this.#closed = true;
    if (this.#closeTimer !== null) { clearTimeout(this.#closeTimer); this.#closeTimer = null; }
    this.emit("close");
  }
}

/** Completes the handshake on an upgraded socket and returns a connection. */
export function acceptWebSocket(req, socket, head = Buffer.alloc(0), options = {}) {
  const accept = websocketAccept(req.headers["sec-websocket-key"]);
  socket.write(
    "HTTP/1.1 101 Switching Protocols\r\n" +
    "Upgrade: websocket\r\n" +
    "Connection: Upgrade\r\n" +
    "Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
  );
  return new WebSocketConnection(socket, head, options);
}
