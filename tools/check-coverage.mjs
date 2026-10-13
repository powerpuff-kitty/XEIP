// Per-file coverage gate.
//
// The repository's `coverage`/`coverage:organization` scripts use Node's
// aggregate thresholds, which a high-coverage majority can satisfy while a
// security-relevant module drops far below the floor. This tool adds a
// per-file floor for a curated set of trust/crypto modules and fails if any
// of them regresses.
//
// Usage:
//   node --test --experimental-test-coverage <tests...> > report.log 2>&1
//   node tools/check-coverage.mjs report.log
//
// It also requires the test summary in the same log to report `fail 0`, so a
// failing run cannot be masked by a passing coverage parse.
//
// Thresholds sit a few points below the values observed at the time the gate
// was added (see PRODUCTION_READINESS.md); tighten them as coverage improves,
// never loosen them silently.

import { readFileSync } from "node:fs";

// path (as it appears in the Node coverage table) -> { lines, branches, funcs }
const CRITICAL = new Map([
  ["packages/identity/key-id.mjs", { lines: 95, branches: 88, funcs: 100 }],
  ["packages/identity/signed-envelope.mjs", { lines: 95, branches: 88, funcs: 100 }],
  ["packages/identity/key-document.mjs", { lines: 95, branches: 85, funcs: 100 }],
  ["packages/identity/identity-status.mjs", { lines: 95, branches: 78, funcs: 100 }],
  ["packages/identity/entity-envelope.mjs", { lines: 95, branches: 85, funcs: 100 }],
  ["packages/identity/trust-state.mjs", { lines: 97, branches: 88, funcs: 100 }],
  ["services/relay/trust.mjs", { lines: 85, branches: 78, funcs: 100 }],
  ["services/relay/relay-core.mjs", { lines: 98, branches: 90, funcs: 94 }],
  ["services/relay/admission.mjs", { lines: 98, branches: 90, funcs: 100 }],
  ["services/relay/durable.mjs", { lines: 97, branches: 85, funcs: 95 }],
  ["services/relay/replay.mjs", { lines: 98, branches: 95, funcs: 100 }],
  ["services/relay/receipts.mjs", { lines: 98, branches: 88, funcs: 100 }],
  ["services/relay/delivery.mjs", { lines: 98, branches: 95, funcs: 100 }],
  ["services/relay/entity-trust.mjs", { lines: 95, branches: 83, funcs: 90 }],
]);

function readInput() {
  const path = process.argv[2];
  if (path && path !== "-") return readFileSync(path, "utf8");
  return readFileSync(0, "utf8");
}

// Use the LAST summary of each counter: a test or fixture printing a line that
// merely looks like `ℹ fail 0` must not shadow the real summary.
function lastCount(text, name) {
  const matches = [...text.matchAll(new RegExp(`^ℹ\\s+${name}\\s+(\\d+)`, "gm"))];
  return matches.length === 0 ? null : Number(matches[matches.length - 1][1]);
}

function parseSummary(text) {
  return {
    fail: lastCount(text, "fail"),
    pass: lastCount(text, "pass"),
    cancelled: lastCount(text, "cancelled"),
  };
}

// Rebuild full relative paths from Node's indented coverage table. Directory
// rows carry no metrics and establish the prefix stack for their children.
function parseCoverage(text) {
  const rows = new Map();
  let inReport = false;
  const stack = [];
  for (const line of text.split("\n")) {
    if (line.includes("start of coverage report")) {
      inReport = true;
      continue;
    }
    if (line.includes("end of coverage report")) {
      inReport = false;
      continue;
    }
    if (!inReport) continue;
    const match = line.match(/^ℹ(\s*)(.*)$/);
    if (!match) continue;
    const indent = match[1].length;
    const cells = match[2].split("|").map((cell) => cell.trim());
    const name = cells[0];
    if (name === "" || name === "file" || name === "all files") continue;
    const metrics = cells.slice(1, 4);
    if (metrics.every((value) => value === "")) {
      stack[indent - 1] = name;
      stack.length = indent;
      continue;
    }
    if (indent < 1) continue;
    const path = [...stack.slice(0, indent - 1), name].join("/");
    rows.set(path, {
      lines: Number(metrics[0]),
      branches: Number(metrics[1]),
      funcs: Number(metrics[2]),
    });
  }
  return rows;
}

function main() {
  const text = readInput();
  const { fail, pass, cancelled } = parseSummary(text);
  const violations = [];

  if (fail === null) {
    violations.push("coverage log has no test summary (`ℹ fail <n>`); did the test run complete?");
  } else if (fail !== 0) {
    violations.push(`test run reported ${fail} failing test(s); coverage gate cannot pass`);
  }
  if (cancelled !== null && cancelled !== 0) {
    violations.push(`test run reported ${cancelled} cancelled test(s); results are incomplete`);
  }

  const rows = parseCoverage(text);
  if (rows.size === 0) {
    violations.push("no coverage rows parsed; report missing or malformed");
  }
  for (const [path, threshold] of CRITICAL) {
    const actual = rows.get(path);
    if (actual === undefined) {
      violations.push(`${path}: missing from coverage report (renamed or removed?)`);
      continue;
    }
    for (const metric of ["lines", "branches", "funcs"]) {
      // A non-numeric cell parses to NaN, and `NaN < x` is false; treat any
      // non-finite metric as a violation so a report-format change fails closed.
      if (!Number.isFinite(actual[metric]) || actual[metric] < threshold[metric]) {
        const shown = Number.isFinite(actual[metric]) ? `${actual[metric].toFixed(2)}%` : "non-numeric";
        violations.push(`${path}: ${metric} ${shown} < required ${threshold[metric]}%`);
      }
    }
  }

  if (violations.length > 0) {
    process.stderr.write("per-file coverage gate FAILED:\n");
    for (const violation of violations) process.stderr.write(`  - ${violation}\n`);
    process.exitCode = 1;
    return;
  }
  process.stdout.write(
    `per-file coverage OK: ${CRITICAL.size} critical modules above floor ` +
      `(${pass ?? "?"} tests passed).\n`,
  );
}

main();
