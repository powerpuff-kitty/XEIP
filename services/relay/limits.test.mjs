import test from "node:test";
import assert from "node:assert/strict";
import { LimitPolicy, LOCAL_LIMITS_PROFILE, MAX_TRACKED_KEYS } from "./limits.mjs";

test("rejects null, unknown keys, non-integers and out-of-range configuration", () => {
  for (const configuration of [null, [], "bad", 7, { extra: true }, { keyBy: "session" }, { keyBy: null },
    { requestsPerSecond: 0 }, { requestsPerSecond: 100001 }, { requestsPerSecond: 1.5 }, { requestsPerSecond: "2" },
    { burst: 0 }, { burst: 100001 }, { burst: 2.5 }, { burst: "2" },
    { maxConnections: 0 }, { maxConnections: 100001 }, { maxConnections: 1.5 }, { maxConnections: "2" },
    { maxSubscriptions: 0 }, { maxSubscriptions: 100001 }, { maxSubscriptions: 1.5 }, { maxSubscriptions: "2" }]) {
    assert.throws(() => new LimitPolicy(configuration), undefined, JSON.stringify(configuration));
  }
});

test("applies the documented defaults and copies its limits", () => {
  assert.equal(LOCAL_LIMITS_PROFILE, "xeip.local-limits/0.1");
  assert.deepEqual(new LimitPolicy().limits,
    { requestsPerSecond: 50, burst: 100, maxConnections: 256, maxSubscriptions: 256, keyBy: "principal" });
  const configuration = { requestsPerSecond: 5, burst: 7, maxConnections: 8, maxSubscriptions: 9, keyBy: "peer" };
  const policy = new LimitPolicy(configuration);
  configuration.requestsPerSecond = 1; configuration.burst = 1; configuration.keyBy = "principal";
  const published = policy.limits;
  published.maxConnections = 1; published.maxSubscriptions = 1;
  assert.deepEqual(policy.limits,
    { requestsPerSecond: 5, burst: 7, maxConnections: 8, maxSubscriptions: 9, keyBy: "peer" });
});

test("allows a burst, denies past it and refills on injected monotonic time", () => {
  const policy = new LimitPolicy({ requestsPerSecond: 10, burst: 3 });
  assert.deepEqual(policy.take("k", 0), { allowed: true, retryAfter: 0 });
  assert.deepEqual(policy.take("k", 0), { allowed: true, retryAfter: 0 });
  assert.deepEqual(policy.take("k", 0), { allowed: true, retryAfter: 0 });
  const denied = policy.take("k", 0);
  assert.equal(denied.allowed, false);
  assert.equal(denied.retryAfter, 1);
  // Half a token is not enough; one whole token is.
  assert.equal(policy.take("k", 50).allowed, false);
  assert.deepEqual(policy.take("k", 100), { allowed: true, retryAfter: 0 });
});

test("never moves the monotonic clock backwards", () => {
  const policy = new LimitPolicy({ requestsPerSecond: 10, burst: 1 });
  assert.equal(policy.take("k", 0).allowed, true);
  assert.equal(policy.take("k", 1000).allowed, true);
  // A smaller elapsed value must not refill the bucket again.
  const stale = policy.take("k", 0);
  assert.equal(stale.allowed, false);
  assert.equal(stale.retryAfter, 1);
});

test("bounds tracked keys and evicts the least-recently-used key", () => {
  const policy = new LimitPolicy({ requestsPerSecond: 1, burst: 1 });
  for (let index = 0; index < MAX_TRACKED_KEYS; index++) {
    assert.equal(policy.take("k" + index, 0).allowed, true);
  }
  // Touch an early key: the initially oldest key (k0) becomes the eviction victim.
  assert.equal(policy.take("k1", 0).allowed, false);
  assert.equal(policy.take("new", 0).allowed, true);
  // The evicted key returns with a fresh full bucket; the touched key is still drained.
  assert.equal(policy.take("k0", 0).allowed, true);
  assert.equal(policy.take("k1", 0).allowed, false);
});

test("acquires and releases bounded connection and subscription counters", () => {
  const policy = new LimitPolicy({ maxConnections: 2, maxSubscriptions: 1 });
  assert.equal(policy.acquireConnection(), true);
  assert.equal(policy.acquireConnection(), true);
  assert.equal(policy.acquireConnection(), false);
  assert.equal(policy.activeConnections, 2);
  policy.releaseConnection();
  assert.equal(policy.activeConnections, 1);
  assert.equal(policy.acquireConnection(), true);
  policy.releaseConnection(); policy.releaseConnection(); policy.releaseConnection();
  assert.equal(policy.activeConnections, 0);
  assert.equal(policy.acquireSubscription(), true);
  assert.equal(policy.acquireSubscription(), false);
  assert.equal(policy.activeSubscriptions, 1);
  policy.releaseSubscription(); policy.releaseSubscription();
  assert.equal(policy.activeSubscriptions, 0);
});

test("derives keys by principal or peer, falling back to the peer without a principal", () => {
  const byPrincipal = new LimitPolicy({ keyBy: "principal" });
  assert.equal(byPrincipal.keyFor({ entity: "urn:xeip:entity:a" }, "127.0.0.1"),
    byPrincipal.keyFor({ entity: "urn:xeip:entity:a" }, "::1"));
  assert.notEqual(byPrincipal.keyFor({ entity: "urn:xeip:entity:a" }, "127.0.0.1"),
    byPrincipal.keyFor({ entity: "urn:xeip:entity:b" }, "127.0.0.1"));
  assert.equal(byPrincipal.keyFor(null, "127.0.0.1"), byPrincipal.keyFor(null, "127.0.0.1"));
  assert.notEqual(byPrincipal.keyFor(null, "127.0.0.1"), byPrincipal.keyFor(null, "::1"));

  const byPeer = new LimitPolicy({ keyBy: "peer" });
  assert.equal(byPeer.keyFor({ entity: "urn:xeip:entity:a" }, "127.0.0.1"),
    byPeer.keyFor({ entity: "urn:xeip:entity:b" }, "127.0.0.1"));
  assert.notEqual(byPeer.keyFor({ entity: "urn:xeip:entity:a" }, "127.0.0.1"),
    byPeer.keyFor({ entity: "urn:xeip:entity:a" }, "::1"));
});

test("rejects invalid elapsed time and invalid keys", () => {
  const policy = new LimitPolicy();
  for (const elapsed of [NaN, Infinity, -1, "1", Number.MAX_VALUE]) {
    assert.throws(() => policy.take("k", elapsed));
  }
  for (const key of [null, "", 7, undefined]) {
    assert.throws(() => policy.take(key, 0));
  }
});
