/**
 * Transport-agnostic core of the XEIP development relay. It owns policy
 * preconditions, the policy handles (replay/delivery/durable/receipts/limits),
 * the session subscriber registry and message/receipt routing. It never imports
 * `node:http` and never references a request, response or socket; transports
 * adapt their own I/O around the outcomes returned here.
 */
import { LocalAdmission, LOCAL_ADMISSION_PROFILE } from "./admission.mjs";
import { ReplayWindow, LOCAL_REPLAY_PROFILE } from "./replay.mjs";
import { DeliveryLog, LOCAL_DELIVERY_PROFILE } from "./delivery.mjs";
import { DurableStore, LOCAL_DURABLE_PROFILE } from "./durable.mjs";
import { ReceiptLedger, LOCAL_RECEIPTS_PROFILE } from "./receipts.mjs";
import { LimitPolicy, LOCAL_LIMITS_PROFILE } from "./limits.mjs";
import { authorize, sseFrame, validateMessage, absoluteUri, MAX_FRAME } from "./http-util.mjs";
import { XEIP_SUPPORTED_VERSIONS } from "../../sdks/typescript/src/validation.js";
import { SIG_EXTENSION, strictParse, verifySignedEnvelope } from "../../tools/signed-envelope.mjs";
import { KeyDocumentTrust } from "../../tools/key-document.mjs";

/**
 * Opt-in signed-envelope enforcement. The carrier, canonical bytes and
 * `entityUrn(kid) === sender` binding are defined by
 * `spec/local-signed-envelopes.md`; verification is the reference
 * implementation in `tools/signed-envelope.mjs`, not re-implemented here.
 */
export const LOCAL_SIGNED_ENVELOPES_PROFILE = "xeip.local-signed-envelopes/0.1";

/**
 * Opt-in trusted-key resolution. When `keyDocuments` is configured, a signed
 * envelope's `kid` must additionally be a *current* root or device key of a
 * trusted chain (verified at construction with `tools/key-document.mjs`), not
 * merely self-certifying.
 */
export const LOCAL_TRUSTED_KEY_DOCUMENTS_PROFILE = "xeip.local-trusted-key-documents/0.1";

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function parseKeyDocument(document) {
  if (typeof document === "string") {
    try {
      return strictParse(document);
    } catch {
      throw new TypeError("trusted key document is not valid JSON");
    }
  }
  return document;
}

/**
 * Verify the trusted provisioning input at construction and build a per-entity
 * view of current root/device kids. Each entity's documents are ingested, in
 * order, through a {@link KeyDocumentTrust} pinned to the anchor supplied for
 * that entity: single-document verification, chain linking and anchor checks
 * all run here. Any invalid or untrusted document throws (fail closed), so no
 * relay is ever constructed around an untrusted chain.
 */
function buildKeyDocumentRegistry(keyDocuments) {
  if (!Array.isArray(keyDocuments) || keyDocuments.length === 0) {
    throw new TypeError("keyDocuments must be a non-empty array");
  }
  const groups = new Map();
  const entityOrder = [];
  for (const entry of keyDocuments) {
    if (!isPlainObject(entry)) throw new TypeError("each keyDocuments entry must be an object");
    for (const key of Object.keys(entry)) {
      if (key !== "document" && key !== "anchor") {
        throw new TypeError(`unknown keyDocuments entry field: ${key}`);
      }
    }
    if (!Object.hasOwn(entry, "document")) {
      throw new TypeError("keyDocuments entry requires a document");
    }
    const document = parseKeyDocument(entry.document);
    if (!isPlainObject(document) || typeof document.entity !== "string") {
      throw new TypeError("trusted key document must carry a string entity");
    }
    let group = groups.get(document.entity);
    if (group === undefined) {
      group = { anchor: entry.anchor, documents: [] };
      groups.set(document.entity, group);
      entityOrder.push(document.entity);
    } else if (group.anchor === undefined && entry.anchor !== undefined) {
      group.anchor = entry.anchor;
    }
    group.documents.push(document);
  }

  const ownerByKid = new Map();
  const kidsByEntity = new Map();
  for (const entity of entityOrder) {
    const group = groups.get(entity);
    const anchor = group.anchor === undefined ? null : group.anchor;
    let trust;
    try {
      trust = new KeyDocumentTrust({ entity, anchor });
    } catch (error) {
      throw new TypeError(`invalid trusted key document anchor for ${entity}: ${error.message}`);
    }
    let current;
    for (const document of group.documents) {
      const result = trust.ingest(document);
      if (!result.valid) {
        throw new Error(`untrusted key document for ${entity}: ${result.reason}`);
      }
      current = document;
    }
    const kids = new Set([...current.roots, ...current.devices]);
    kidsByEntity.set(entity, kids);
    for (const kid of kids) {
      const existing = ownerByKid.get(kid);
      if (existing !== undefined && existing !== entity) {
        throw new Error(`key ${kid} is endorsed by multiple entities`);
      }
      ownerByKid.set(kid, entity);
    }
  }
  return { ownerByKid, entityCount: kidsByEntity.size };
}

// The verified signature kid, or undefined. The carrier is authenticated by the
// time this is read, but a defensive shape check keeps a malformed value from
// throwing on the routing path.
const envelopeKid = raw => {
  const carrier = isPlainObject(raw) && isPlainObject(raw.extensions)
    ? raw.extensions[SIG_EXTENSION]
    : undefined;
  return isPlainObject(carrier) ? carrier.kid : undefined;
};

const RECEIPT_FIELDS = ["session", "seq", "id", "status"];
// Reserve room for the SSE `id:` line and the WebSocket message wrapper so the
// exact emitted frame stays within MAX_FRAME across both transports.
const FRAME_OVERHEAD = 96;
// Shared-token mode has no authenticated principal, but routing and limit keys
// must still see a truthy authorization result. This sentinel carries no entity,
// so `LimitPolicy.keyFor` falls back to the peer exactly as a null principal did.
const TOKEN_PRINCIPAL = Object.freeze({ token: true });

/**
 * Builds the policy core. The option precondition matrix and every policy
 * constructor run synchronously, so a misconfiguration throws here before any
 * transport is created.
 */
export function createRelayCore({ token, admission, replay, delivery, durable, receipts, limits, signatures, keyDocuments }) {
  // `signatures` is a bare opt-in. An empty object enables detached-signature
  // enforcement; null, arrays, primitives and any unknown member are rejected.
  // It is orthogonal to the authentication modes and needs no other profile.
  if (signatures !== undefined &&
      (signatures === null || typeof signatures !== "object" || Array.isArray(signatures) ||
       Object.keys(signatures).length > 0)) {
    throw new TypeError("invalid signatures configuration");
  }
  const signaturesEnabled = signatures !== undefined;
  // Trusted key resolution is a tightening of signed-envelope enforcement, so
  // it is meaningless (and rejected) without `signatures`. The documents are
  // verified here, before any transport exists, and fail closed.
  if (keyDocuments !== undefined && !signaturesEnabled) {
    throw new TypeError("keyDocuments requires signatures");
  }
  const keyDocRegistry = keyDocuments === undefined ? null : buildKeyDocumentRegistry(keyDocuments);
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
  // The durable store holds an exclusive `<dir>/LOCK` and an open fd. Every later
  // policy construction (receipts, limits) can throw on invalid configuration, so
  // close the store before rethrowing rather than leaking its lock or fd.
  let store, receiptBackend, receiptLedger, limitPolicy;
  try {
    store = durableStore ?? deliveryLog;
    // Receipts persist through the durable store's directory only when both
    // options are set; without a durable backend the ledger stays in-memory.
    receiptBackend = durableStore && receipts !== undefined ? durableStore.openReceiptLog() : null;
    receiptLedger = receipts === undefined ? null : new ReceiptLedger(receipts, receiptBackend);
    limitPolicy = limits === undefined ? null : new LimitPolicy(limits);
  } catch (error) {
    durableStore?.close();
    throw error;
  }
  // One token-bucket decision for the current request's rate-limit key, or null
  // when the profile is disabled. The transport supplies the peer address; the
  // policy itself stays unaware of transports and principals.
  const limitDecision = (principal, peer) =>
    limitPolicy === null ? null : limitPolicy.take(limitPolicy.keyFor(principal, peer));
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
  const clientsFor = session => sessions.get(session) ?? [];
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
  // Returns an error outcome or an acceptance body; it never performs transport writes.
  const routeMessage = (principal, raw) => {
    const error = validateMessage(raw);
    if (error) return { status: 422, error };
    // Authentication is checked before the signature so a revoked credential is
    // still reported as 401; the signature is verified before any authorization,
    // replay recording or delivery.
    if (admission && !admission.isCurrent(principal)) return { status: 401, error: "unauthorized" };
    if (signaturesEnabled) {
      let verified;
      try { verified = verifySignedEnvelope(raw); }
      catch { return { status: 422, error: "invalid signature" }; }
      if (!verified.valid) {
        // A signer/key-to-sender mismatch is an authorization denial; every
        // other verification failure is an unacceptable envelope.
        return verified.reason === "sender binding"
          ? { status: 403, error: "forbidden" }
          : { status: 422, error: "invalid signature" };
      }
    }
    // With trusted key documents configured, the verified `kid` must also be a
    // current root or device key of a trusted chain, not merely self-certifying.
    // This composes with, and does not replace, the `entityUrn(kid) === sender`
    // binding enforced by `verifySignedEnvelope`. Revocation/status is out of
    // scope here and is a future integration.
    if (keyDocRegistry && !keyDocRegistry.ownerByKid.has(envelopeKid(raw))) {
      return { status: 403, error: "forbidden" };
    }
    if (admission && !admission.canSend(principal, raw)) return { status: 403, error: "forbidden" };
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
    for (const subscriber of clientsFor(raw.session)) {
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
  const health = () => {
    const protocol = "xeip/" + XEIP_SUPPORTED_VERSIONS[0];
    const base = admission
      ? { status: "ok", protocol, mode: "local-admission", profile: LOCAL_ADMISSION_PROFILE,
        transports: ["http-sse", "websocket"],
        ...(replayWindow ? { deliveryProfile: LOCAL_REPLAY_PROFILE, replay: replayWindow.limits } : {}) }
      : { status: "ok", protocol, mode: "development-only", transports: ["http-sse", "websocket"] };
    base.protocolVersions = XEIP_SUPPORTED_VERSIONS;
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
    if (signaturesEnabled) base.signatureProfile = LOCAL_SIGNED_ENVELOPES_PROFILE;
    if (keyDocRegistry) {
      base.keyDocumentProfile = LOCAL_TRUSTED_KEY_DOCUMENTS_PROFILE;
      // Advertise only the count: no per-entity key ids or chain material.
      base.keyDocuments = { entities: keyDocRegistry.entityCount };
    }
    return base;
  };
  const checkSubscriptions = () => {
    for (const [session, clients] of sessions) for (const client of clients) {
      if (!admission.canSubscribe(client.principal, session)) client.destroy();
    }
  };
  // Shared-token mode returns a truthy sentinel carrying no entity; admission
  // mode returns the authenticated principal or null.
  const authenticate = header =>
    admission ? admission.authenticate(header) : (authorize(header, token) ? TOKEN_PRINCIPAL : null);
  // Admission delegations. They are only called by callers already guarded by
  // admission mode, matching the original inline call sites.
  const isCurrent = principal => admission.isCurrent(principal);
  const canSubscribe = (principal, session) => admission.canSubscribe(principal, session);
  const sendAllowed = (principal, message) => admission.canSend(principal, message);
  return {
    signaturesEnabled,
    keyDocRegistry,
    authenticate,
    isCurrent,
    canSubscribe,
    sendAllowed,
    routeMessage,
    routeReceipt,
    health,
    checkSubscriptions,
    addClient,
    removeClient,
    clientsFor,
    activeCounts,
    limitDecision,
    admission,
    store,
    receiptLedger,
    replayWindow,
    limitPolicy,
    durableStore
  };
}
