// Coordinate only resources explicitly registered by disposable conformance fixtures.
const callbacks = new Set();
let stopping;
async function interrupted() {
  if (stopping) return;
  stopping = (async () => {
    let failed = false;
    for (const callback of [...callbacks].reverse()) {
      try {
        await callback();
      } catch {
        failed = true;
      }
    }
    if (failed)
      process.stderr.write(
        "Owned fixture cleanup failed; inspect remaining xeip fixture resources.\n",
      );
    process.exit(1);
  })();
  await stopping;
}
export function registerFixtureCleanup(callback) {
  if (typeof callback !== "function" || stopping)
    throw new Error("fixture cleanup unavailable");
  if (callbacks.size === 0) {
    process.on("SIGINT", interrupted);
    process.on("SIGTERM", interrupted);
  }
  callbacks.add(callback);
  return () => {
    callbacks.delete(callback);
    if (callbacks.size === 0 && !stopping) {
      process.removeListener("SIGINT", interrupted);
      process.removeListener("SIGTERM", interrupted);
    }
  };
}
