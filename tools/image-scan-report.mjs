import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

export function imageScanEvidence(report) {
  const target = {};
  for (const key of ["imageID", "manifestDigest"]) {
    const value = report?.source?.target?.[key];
    if (typeof value === "string" && /^sha256:[a-f0-9]{64}$/.test(value)) {
      target[key] = value;
    }
  }
  // Grype embeds the full image config (including Env/history) in source.target.
  // Retain identity by allowlist, never copy that metadata to CI artifacts.
  return { ...report, source: { type: report?.source?.type, target } };
}

// A successful process alone is not evidence of a completed, validated scan.
export function assessImageScan(report, scannerExit) {
  const descriptor = report?.descriptor;
  const database = descriptor?.configuration?.db;
  if (
    descriptor?.name !== "grype" ||
    descriptor?.db?.status?.valid !== true ||
    database?.["validate-by-hash-on-start"] !== true ||
    database?.["validate-age"] !== true ||
    report?.source?.type !== "image" ||
    !Array.isArray(report?.matches)
  )
    throw new Error("Incomplete image scan or unvalidated database");
  const counts = {};
  for (const match of report.matches) {
    const severity = match?.vulnerability?.severity;
    if (
      !["Negligible", "Low", "Medium", "High", "Critical"].includes(severity)
    ) {
      throw new Error("Unassessed vulnerability severity");
    }
    counts[severity] = (counts[severity] ?? 0) + 1;
  }
  return {
    exitCode:
      scannerExit !== 0
        ? scannerExit === 2
          ? 2
          : 1
        : counts.High || counts.Critical
          ? 2
          : 0,
    counts,
  };
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  try {
    const report = JSON.parse(readFileSync(process.argv[2], "utf8"));
    writeFileSync(
      process.argv[4],
      JSON.stringify(imageScanEvidence(report), null, 2) + "\n",
      {
        flag: "wx",
        mode: 0o600,
      },
    );
    const result = assessImageScan(
      report,
      /^\d+$/.test(process.argv[3] ?? "") ? Number(process.argv[3]) : null,
    );
    console.log(JSON.stringify(result, null, 2));
    process.exitCode = result.exitCode;
  } catch {
    console.error(
      "Image scan gate failed: missing, invalid or unassessed evidence",
    );
    process.exitCode = 1;
  }
}
