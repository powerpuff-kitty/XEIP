import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

// Shared immutable migration manifest: startup verifies without executing owner DDL.
export const migrations = Object.freeze(
  ["001-actions.sql", "002-results.sql", "003-control.sql"].map((file) => {
    const sql = readFileSync(
      new URL("./migrations/" + file, import.meta.url),
      "utf8",
    );
    return Object.freeze({
      sql,
      checksum: createHash("sha256").update(sql).digest("hex"),
    });
  }),
);
