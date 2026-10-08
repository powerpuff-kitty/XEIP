import { createHash, timingSafeEqual } from "node:crypto";
import { requireUri, validateSession } from "../../sdks/typescript/src/validation.js";

export const LOCAL_ADMISSION_PROFILE = "xeip.local-admission/0.1";
const MAX_ENTITIES = 256, MAX_SESSIONS = 256, MAX_HISTORY = 4096;
const digest = token => createHash("sha256").update(token, "utf8").digest();

function requireToken(token) {
  if (typeof token !== "string" || !/^[A-Za-z0-9_-]{43,128}$/.test(token)) {
    throw new TypeError("credential token must contain 43–128 base64url characters");
  }
}

function requireRecord(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).some(key => !keys.includes(key))) throw new TypeError("invalid admission configuration");
}

export class LocalAdmission {
  #credentials = new Map();
  #sessions = new Map();
  #history = new Set();
  #listeners = new Set();

  constructor(configuration) {
    requireRecord(configuration, ["credentials", "sessions"]);
    const { credentials, sessions } = configuration;
    if (!Array.isArray(credentials) || credentials.length < 1 || credentials.length > MAX_ENTITIES ||
        !Array.isArray(sessions) || sessions.length > MAX_SESSIONS) throw new TypeError("invalid credential/session count");
    for (const credential of credentials) {
      requireRecord(credential, ["entity", "token"]);
      const { entity, token } = credential;
      requireUri(entity, "credential entity");
      if (this.#credentials.has(entity)) throw new TypeError("duplicate credential entity");
      this.#installCredential(entity, token);
    }
    for (const session of sessions) {
      const snapshot = this.#snapshot(session);
      if (this.#sessions.has(snapshot.id)) throw new TypeError("duplicate session ID");
      this.#sessions.set(snapshot.id, snapshot);
    }
  }

  #installCredential(entity, token) {
    requireToken(token);
    const hash = digest(token), key = hash.toString("hex");
    if (this.#history.has(key)) throw new TypeError("credential token was already issued");
    if (this.#history.size >= MAX_HISTORY) throw new RangeError("credential history limit reached");
    const record = { principal: Object.freeze({ entity }), hash, active: true };
    this.#history.add(key);
    this.#credentials.set(entity, record);
  }

  #snapshot(session) {
    validateSession(session);
    const serialized = JSON.stringify(session);
    if (Buffer.byteLength(serialized) > 64 * 1024) throw new RangeError("session descriptor exceeds 64 KiB");
    const snapshot = JSON.parse(serialized);
    // Serialization hooks/getters must not turn validated input into invalid policy state.
    validateSession(snapshot);
    if (snapshot.mode === "direct" && snapshot.members.length !== 2) throw new TypeError("direct session requires two members");
    if (snapshot.members.some(entity => !this.#credentials.has(entity))) throw new TypeError("unregistered session member");
    return snapshot;
  }

  authenticate(header) {
    if (typeof header !== "string" || !header.startsWith("Bearer ")) return null;
    const token = header.slice(7);
    if (!/^[A-Za-z0-9_-]{43,128}$/.test(token)) return null;
    const provided = digest(token);
    let principal = null;
    for (const record of this.#credentials.values()) {
      if (timingSafeEqual(provided, record.hash) && record.active) principal = record.principal;
    }
    return principal;
  }

  isCurrent(principal) {
    if (!principal || typeof principal !== "object") return false;
    const record = this.#credentials.get(principal.entity);
    return record?.active === true && record.principal === principal;
  }

  canSubscribe(principal, session) {
    return this.isCurrent(principal) && (this.#sessions.get(session)?.members.includes(principal.entity) ?? false);
  }

  canSend(principal, message) {
    if (!message || !this.canSubscribe(principal, message.session) || message.sender !== principal.entity) return false;
    return message.recipient === undefined || this.#sessions.get(message.session).members.includes(message.recipient);
  }

  revokeCredential(entity) {
    const record = this.#credentials.get(entity);
    if (!record) throw new TypeError("unknown credential entity");
    if (record.active) { record.active = false; this.#changed(); }
  }

  rotateCredential(entity, token) {
    if (!this.#credentials.has(entity)) throw new TypeError("unknown credential entity");
    this.#installCredential(entity, token);
    this.#changed();
  }

  setMembers(session, members) {
    const previous = this.#sessions.get(session);
    if (!previous) throw new TypeError("unknown session");
    const snapshot = this.#snapshot({ ...previous, members });
    this.#sessions.set(session, snapshot);
    this.#changed();
  }

  onChange(listener) {
    if (typeof listener !== "function") throw new TypeError("change listener must be a function");
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  #changed() {
    const failures = [];
    for (const listener of [...this.#listeners]) {
      try { listener(); } catch (error) { failures.push(error); }
    }
    // Policy is already committed. Cleanup observers must run even if another owner observer fails.
    if (failures.length) throw new AggregateError(failures, "admission change observers failed after policy update");
  }
}
