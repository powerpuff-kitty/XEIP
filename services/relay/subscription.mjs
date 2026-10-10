/**
 * Shared subscription lifecycle for the two relay transports.
 *
 * The HTTP/SSE `/events` handler and the WebSocket `subscribe` control open a
 * subscription identically: validate the session and entity selectors, refuse a
 * resume cursor when no delivery profile is enabled, re-check admission, enforce
 * the aggregate and per-entity caps, account for a replaced slot, register the
 * transport client and compute the filtered resume backlog. They differ only in
 * cursor syntax, how a client writes, how the backlog is framed and how the
 * transport connection slot is held; those are supplied as transport hooks and
 * the resumed backlog is returned as neutral data for the caller to frame.
 */
import { absoluteUri } from "./http-util.mjs";

// Aggregate and per-entity subscription caps enforced by admission mode.
const MAX_TOTAL_SUBSCRIPTIONS = 256;
const MAX_ENTITY_SUBSCRIPTIONS = 4;

const fail = (status, error) => ({ error: { status, error } });

/**
 * Opens one subscription against the transport-agnostic core.
 *
 * Transport hooks (all optional except `client`):
 *   readAfter()  parses the transport cursor after selector validation and
 *                returns { after } or { error: { status, error } }.
 *   recheckCurrent  re-verify a revocation-prone credential before subscribing
 *                (WebSocket only).
 *   reserve()    claims the transport connection slot once validation and quota
 *                checks pass; returns a { status, error } refusal or nothing.
 *   release()    undoes `reserve` when the subscription slot cannot be claimed
 *                and on close.
 *
 * @returns { error, terminate? } when refused, otherwise
 *          { client, storedEntity, resume, close }; `resume` is undefined
 *          without a cursor, else { gap, from, backlog: [{ seq, message }] }.
 */
export function openSubscription(core, {
  principal, session, entity, client, previous,
  readAfter, recheckCurrent = false, reserve, release
}) {
  if (!absoluteUri(session) || !absoluteUri(entity)) return fail(400, "valid session and entity URIs required");
  const cursor = readAfter ? readAfter() : { after: undefined };
  if (cursor.error) return { error: cursor.error };
  const after = cursor.after;
  if (after !== undefined && !core.store) return fail(400, "delivery resume profile not enabled");
  if (core.admission) {
    if (recheckCurrent && !core.isCurrent(principal)) return { error: { status: 401, error: "unauthorized" }, terminate: true };
    if (entity !== principal.entity || !core.canSubscribe(principal, session)) return fail(403, "forbidden");
    const { total, entityStreams } = core.activeCounts(principal.entity);
    if (total >= MAX_TOTAL_SUBSCRIPTIONS || entityStreams >= MAX_ENTITY_SUBSCRIPTIONS) {
      return fail(429, "subscription limit reached");
    }
  }
  if (reserve) {
    const denied = reserve();
    if (denied) return { error: denied };
  }
  // Replacing an existing subscription keeps its held slot; a brand new
  // subscription must fit the shared subscription cap.
  if (!previous && core.limitPolicy && !core.limitPolicy.acquireSubscription()) {
    release?.();
    return fail(429, "subscription limit exceeded");
  }
  if (previous) core.removeClient(session, previous);
  // Only admission mode derives the stored identity from authenticated credentials.
  const storedEntity = core.admission ? principal.entity : entity;
  client.entity = storedEntity;
  core.addClient(session, client);
  let resume;
  if (after !== undefined) {
    const { entries, gap, from } = core.store.since(session, after);
    resume = {
      gap,
      from,
      backlog: entries.filter(entry => entry.message.recipient === undefined || entry.message.recipient === storedEntity)
    };
  }
  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    core.removeClient(session, client);
    if (core.limitPolicy) core.limitPolicy.releaseSubscription();
    release?.();
  };
  return { client, storedEntity, resume, close };
}
