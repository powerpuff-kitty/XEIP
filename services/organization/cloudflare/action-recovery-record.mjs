/** Platform-neutral historical action recovery codec. No execution capabilities. */
import { createHash } from "node:crypto";
import {
  canonicalize,
  sealEntry,
  PART_BYTES,
  exact,
  validateEntry,
  validateAppend,
} from "./recovery-record.mjs";
import { validateActionEvidence, ACTION_PAGE_BYTES } from "./action-export.mjs";
import { strictParse } from "../../../sdks/typescript/dist/identity.js";
import { snapshot } from "../actions.mjs";
/** @typedef {import('./recovery-record.mjs').Head} Head */
/** @param {string} organization @param {number} sequence @param {unknown} record */
export function actionRecoveryPayload(organization, sequence, record) {
  const checked = validateActionEvidence(record, sequence);
  if (checked.history.at(-1)?.sequence !== sequence)
    throw new TypeError("invalid recovery transition");
  return canonicalize({
    schema: "xeip.action-recovery/1",
    organization,
    sequence,
    record: checked,
  });
}
/** Deterministic data identity, never an execution capability. @param {string} payloadDigest */
export function actionRecoveryId(payloadDigest) {
  if (
    typeof payloadDigest !== "string" ||
    !/^[0-9a-f]{64}$/.test(payloadDigest)
  )
    throw new TypeError("invalid recovery payload digest");
  const hex = createHash("sha256")
    .update("XEIP action recovery UUID v1\n" + payloadDigest)
    .digest("hex");
  return (
    hex.slice(0, 8) +
    "-" +
    hex.slice(8, 12) +
    "-8" +
    hex.slice(13, 16) +
    "-" +
    ((parseInt(hex[16], 16) & 3) | 8).toString(16) +
    hex.slice(17, 20) +
    "-" +
    hex.slice(20, 32)
  );
}
/** @param {string} payload @param {Head} head @param {number} totalBytes */
export function prepareActionRecovery(payload, head, totalBytes) {
  const data = Buffer.from(payload),
    payloadDigest = createHash("sha256").update(data).digest("hex"),
    id = actionRecoveryId(payloadDigest);
  const chunks = [];
  for (let i = 0; i < data.length; i += PART_BYTES)
    chunks.push(data.subarray(i, i + PART_BYTES).toString("base64"));
  const request = {
    expected: head,
    id,
    bytes: data.length,
    payloadDigest,
    chunks,
  };
  const entry = sealEntry({
    schema: "xeip.recovery-entry/1",
    organization: head.organization,
    stream: head.stream,
    sequence: head.sequence + 1,
    id,
    previous: head.checksum,
    payloadDigest,
    bytes: data.length,
    parts: chunks.length,
    totalBytes: totalBytes + data.length,
  });
  return { request, entry };
}
/** @param {unknown} value @param {import('./recovery-record.mjs').Options} options */
export function decodeActionRecovery(value, options) {
  const v = exact(value, ["entry", "chunks"]),
    entry = validateEntry(v.entry, options);
  if (entry.bytes > ACTION_PAGE_BYTES)
    throw new TypeError("invalid action recovery size");
  const { chunks } = validateAppend(
    {
      expected: {
        organization: entry.organization,
        stream: entry.stream,
        sequence: entry.sequence - 1,
        checksum: entry.previous,
      },
      id: entry.id,
      bytes: entry.bytes,
      payloadDigest: entry.payloadDigest,
      chunks: v.chunks,
    },
    options,
  );
  const data = Buffer.concat(
    chunks.map((chunk) => Buffer.from(chunk, "base64")),
  );
  const payload = new TextDecoder("utf-8", {
    fatal: true,
    ignoreBOM: true,
  }).decode(data);
  const input = exact(snapshot(strictParse(payload), ACTION_PAGE_BYTES), [
    "schema",
    "organization",
    "sequence",
    "record",
  ]);
  if (
    input.schema !== "xeip.action-recovery/1" ||
    input.organization !== options.organization ||
    input.sequence !== entry.sequence ||
    actionRecoveryId(entry.payloadDigest) !== entry.id
  )
    throw new TypeError("invalid action recovery record");
  const record = validateActionEvidence(input.record, entry.sequence);
  if (
    actionRecoveryPayload(options.organization, entry.sequence, record) !==
    payload
  )
    throw new TypeError("invalid action recovery encoding");
  return { entry, chunks, record, payload };
}
