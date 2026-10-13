/** PostgreSQL control history. Historical verification does not confer live trust. */
import { createHash } from "node:crypto";
import { canonicalize } from "../../packages/identity/signed-envelope.mjs";
import { snapshot } from "./actions.mjs";
import { prepareControlInWorker } from "./control-preparation.mjs";
import { StoreConflict, StoreUnavailable } from "./errors.mjs";
import { boundedPool, transaction } from "./transactions.mjs";
/** @typedef {import('./transactions.mjs').TransactionPool} Pool */
/** @typedef {import('pg').PoolClient} Client */
/** @typedef {import('./control-state.mjs').Prepared} Prepared */
/** @typedef {{revision:number,digest:string}} Token */
/** @typedef {Token & {snapshot:Prepared}} Current */
/** @typedef {{authority:import('./control-state.mjs').PublicAuthority,provisioning:unknown,acceptedAt:number}} Input */
const zero = "0".repeat(64);
const hashPattern = /^[a-f0-9]{64}$/;

/** Read only explicit JSON data fields, without invoking accessors.
 * @param {unknown} input @param {string[]} required @param {string[]} [optional]
 * @returns {Record<string,unknown>} */
function fields(input, required, optional = []) {
  if (
    !input ||
    typeof input !== "object" ||
    Array.isArray(input) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(input)) ||
    Object.getOwnPropertySymbols(input).length
  )
    throw new StoreUnavailable();
  const descriptors = Object.getOwnPropertyDescriptors(input);
  if (
    required.some((key) => !Object.hasOwn(descriptors, key)) ||
    Object.keys(descriptors).some(
      (key) => !required.includes(key) && !optional.includes(key),
    )
  )
    throw new StoreUnavailable();
  const result = Object.create(null);
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (!("value" in descriptor) || !descriptor.enumerable)
      throw new StoreUnavailable();
    result[key] = descriptor.value;
  }
  return result;
}

/** Keep the pure model's independent section budgets during acquisition waits.
 * @param {unknown} input @param {boolean} [enrollment] */
function copyInput(input, enrollment = false) {
  const raw = fields(input, [
    "authority",
    "provisioning",
    "acceptedAt",
    ...(enrollment ? ["retainedRecords"] : []),
  ]);
  const authority = fields(raw.authority, ["value", "canonical", "digest"]);
  return {
    authority: {
      value: snapshot(authority.value, 4 * 1024 * 1024, 262144),
      canonical: snapshot(authority.canonical, 8 * 1024 * 1024, 1),
      digest: snapshot(authority.digest, 128, 1),
    },
    provisioning: snapshot(raw.provisioning, 8 * 1024 * 1024, 262144),
    acceptedAt: snapshot(raw.acceptedAt, 32, 1),
    ...(enrollment
      ? {
          retainedRecords: snapshot(
            raw.retainedRecords,
            8 * 1024 * 1024,
            32768,
          ),
        }
      : {}),
  };
}

/** @param {unknown} value @returns {number} */
function revision(value) {
  if (typeof value !== "string" || !/^[1-9][0-9]{0,15}$/.test(value))
    throw new StoreUnavailable();
  const result = Number(value);
  if (!Number.isSafeInteger(result)) throw new StoreUnavailable();
  return result;
}

/** @param {number} revision @param {string} previousDigest @param {string} stateDigest */
export function controlEventDigest(revision, previousDigest, stateDigest) {
  if (
    !Number.isSafeInteger(revision) ||
    revision < 1 ||
    typeof previousDigest !== "string" ||
    !hashPattern.test(previousDigest) ||
    typeof stateDigest !== "string" ||
    !hashPattern.test(stateDigest)
  )
    throw new StoreUnavailable();
  return createHash("sha256")
    .update(
      `XEIP organization control event v1\n${revision}\n${previousDigest}\n${stateDigest}`,
    )
    .digest("hex");
}

/** @param {unknown} input @returns {Token} */
function token(input) {
  // Copy data properties before async work. A Current is also a token.
  if (!input || typeof input !== "object") throw new StoreConflict();
  const r = Object.getOwnPropertyDescriptor(input, "revision");
  const d = Object.getOwnPropertyDescriptor(input, "digest");
  if (
    !r ||
    !d ||
    !("value" in r) ||
    !("value" in d) ||
    !Number.isSafeInteger(r.value) ||
    r.value < 1 ||
    typeof d.value !== "string" ||
    !hashPattern.test(d.value)
  )
    throw new StoreConflict();
  return Object.freeze({ revision: r.value, digest: d.value });
}

/** @param {Token} actual @param {Token} expected */
function sameHead(actual, expected) {
  if (
    actual.revision !== expected.revision ||
    actual.digest !== expected.digest
  )
    throw new StoreConflict();
}

/** @param {Client} client @param {'share'|'update'} lock @param {AbortSignal} [signal] @returns {Promise<Current | null>} */
async function readCurrent(client, lock, signal) {
  const head = await client.query(
    `SELECT revision::text, digest FROM xeip_org.control_head WHERE singleton FOR ${lock === "update" ? "UPDATE" : "SHARE"}`,
  );
  if (head.rows.length === 0) {
    const events = await client.query(
      "SELECT 1 FROM xeip_org.control_events LIMIT 1",
    );
    if (events.rows.length) throw new StoreUnavailable();
    return null;
  }
  if (head.rows.length !== 1) throw new StoreUnavailable();
  const currentRevision = revision(head.rows[0].revision);
  const result = await client.query(
    "SELECT revision::text,previous_digest,state_canonical,state_digest,digest FROM xeip_org.control_events WHERE revision=$1",
    [currentRevision],
  );
  const event = result.rows[0];
  if (
    result.rows.length !== 1 ||
    !event ||
    event.digest !== head.rows[0].digest
  )
    throw new StoreUnavailable();
  // Verify the head and its immediate predecessor transition together so retained
  // records are checked for inactive entities too. This is bounded (two events);
  // full ordered history verification remains the separate recovery task.
  let previous;
  if (currentRevision === 1) {
    if (event.previous_digest !== zero) throw new StoreUnavailable();
  } else {
    const prior = await client.query(
      "SELECT digest,state_canonical FROM xeip_org.control_events WHERE revision=$1",
      [currentRevision - 1],
    );
    if (prior.rows.length !== 1 || prior.rows[0].digest !== event.previous_digest)
      throw new StoreUnavailable();
    previous = prior.rows[0].state_canonical;
  }
  const prepared = await prepareControlInWorker(
    "verify",
    previous === undefined
      ? { canonical: event.state_canonical }
      : { canonical: event.state_canonical, previous },
    signal,
  );
  if (
    prepared.digest !== event.state_digest ||
    controlEventDigest(
      currentRevision,
      event.previous_digest,
      prepared.digest,
    ) !== event.digest
  )
    throw new StoreUnavailable();
  if (currentRevision === 1) {
    if (prepared.state.operation !== "enroll") throw new StoreUnavailable();
  } else if (prepared.state.operation === "enroll") {
    throw new StoreUnavailable();
  }
  const future = await client.query(
    "SELECT 1 FROM xeip_org.control_events WHERE revision>$1 LIMIT 1",
    [currentRevision],
  );
  if (future.rows.length) throw new StoreUnavailable();
  return Object.freeze({
    revision: currentRevision,
    digest: event.digest,
    snapshot: prepared,
  });
}

/** @param {Client} client @param {Prepared} prepared @param {Token | null} previous @returns {Promise<Current>} */
async function append(client, prepared, previous) {
  const next = (previous?.revision ?? 0) + 1;
  const previousDigest = previous?.digest ?? zero;
  const digest = controlEventDigest(next, previousDigest, prepared.digest);
  // The trigger publishes the singleton head in this same statement.
  await client.query(
    "INSERT INTO xeip_org.control_events(revision,previous_digest,state_canonical,state_digest,digest) VALUES($1,$2,$3,$4,$5)",
    [next, previousDigest, prepared.canonical, prepared.digest, digest],
  );
  return Object.freeze({ revision: next, digest, snapshot: prepared });
}

/** Signal cancellation never weakens the shared synchronous durability contract.
 * @template T @param {Pool} pool @param {AbortSignal|undefined} signal @param {(client:Client)=>Promise<T>} work */
async function controlTransaction(pool, signal, work) {
  const check = () => {
    if (signal?.aborted) throw new StoreUnavailable();
  };
  check();
  const result = await transaction(
    pool,
    async (client) => {
      check();
      return work(client);
    },
    async () => check(),
  );
  check();
  return result;
}

export class ControlStore {
  /** @type {Pool} */
  #pool;
  /** @param {Pool} pool */
  constructor(pool) {
    boundedPool(pool);
    this.#pool = pool;
  }

  /** Historical head for owner reconciliation; does not confer live authority.
   * @param {{signal?:AbortSignal}} [options] */
  async inspect({ signal } = {}) {
    return controlTransaction(this.#pool, signal, (client) =>
      readCurrent(client, "share", signal),
    );
  }

  /** @param {Input & {retainedRecords:unknown}} input @param {{signal?:AbortSignal}} [options] */
  async enroll(input, { signal } = {}) {
    // Prepare before pool acquisition so mutation during the wait cannot affect publication.
    let prepared;
    try {
      prepared = await prepareControlInWorker(
        "prepare",
        {
          ...copyInput(input, true),
          operation: "enroll",
        },
        signal,
      );
    } catch {
      throw new StoreUnavailable();
    }
    return controlTransaction(this.#pool, signal, async (client) => {
      await client.query("SELECT pg_advisory_xact_lock(1480935760,2)");
      if (await readCurrent(client, "update", signal))
        throw new StoreConflict();
      return append(client, prepared, null);
    });
  }

  /** Compare exact current public inputs. Live freshness belongs to the trust adapter.
   * @param {Input} input @param {{signal?:AbortSignal}} [options] */
  async open(input, { signal } = {}) {
    let expected;
    try {
      const copy = copyInput(input);
      expected = { authority: copy.authority, provisioning: copy.provisioning };
    } catch {
      throw new StoreUnavailable();
    }
    const expectedCanonical = canonicalize(expected);
    return controlTransaction(this.#pool, signal, async (client) => {
      const current = await readCurrent(client, "share", signal);
      if (!current) throw new StoreUnavailable();
      const state = current.snapshot.state;
      const authority = {
        value: state.authority,
        canonical: canonicalize(state.authority),
        digest: state.authorityDigest,
      };
      if (
        canonicalize({ authority, provisioning: state.provisioning }) !==
        expectedCanonical
      )
        throw new StoreConflict();
      return current;
    });
  }

  /** @param {Token} expected @param {Input} input @param {{signal?:AbortSignal}} [options] */
  async publishTrust(expected, input, { signal } = {}) {
    return this.#publish(expected, input, "trust", signal);
  }
  /** Owner-only in SQL. Runtime draining/maintenance leasing are composed separately.
   * @param {Token} expected @param {Input} input @param {{signal?:AbortSignal}} [options] */
  async changeAuthority(expected, input, { signal } = {}) {
    return this.#publish(expected, input, "authority", signal);
  }

  /** @param {Token} expected @param {Input} input @param {'trust'|'authority'} operation @param {AbortSignal} [signal] */
  async #publish(expected, input, operation, signal) {
    const prior = token(expected);
    let copy;
    try {
      copy = copyInput(input);
    } catch {
      throw new StoreUnavailable();
    }
    return controlTransaction(this.#pool, signal, async (client) => {
      // Same order as SQL: publication advisory lock, then singleton row lock.
      await client.query("SELECT pg_advisory_xact_lock(1480935760,2)");
      const current = await readCurrent(client, "update", signal);
      if (!current) throw new StoreUnavailable();
      sameHead(current, prior);
      const prepared = await prepareControlInWorker(
        "prepare",
        {
          ...copy,
          previous: current.snapshot.canonical,
          operation,
        },
        signal,
      );
      return append(client, prepared, current);
    });
  }

  /** Durable use-time head check before dispatch preparation.
   * @param {Token} expected */
  async checkCurrent(expected) {
    const prior = token(expected);
    await controlTransaction(this.#pool, undefined, (client) =>
      this.assertCurrent(client, prior),
    );
  }

  /** Cheap fence inside an existing action transaction; caller owns commit.
   * @param {Client} client @param {Token} expected */
  async assertCurrent(client, expected) {
    const prior = token(expected);
    const result = await client.query(
      "SELECT revision::text,digest FROM xeip_org.control_head WHERE singleton FOR SHARE",
    );
    if (result.rows.length !== 1) throw new StoreUnavailable();
    sameHead(
      {
        revision: revision(result.rows[0].revision),
        digest: result.rows[0].digest,
      },
      prior,
    );
  }
}
