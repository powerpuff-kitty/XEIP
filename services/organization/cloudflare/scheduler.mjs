/** Dedicated privileged Cron Worker. Do not grant its default binding to public callers. */
/** @typedef {{REFRESH:{refresh:()=>Promise<string>}}} Env */
/** @type {ExportedHandler<Env>} */
const handler = {
  fetch() {
    return Response.json(
      { error: "not_found" },
      { status: 404, headers: { "cache-control": "no-store" } },
    );
  },
  async scheduled(_controller, env) {
    let outcome;
    try {
      outcome = await env.REFRESH.refresh();
    } catch {
      throw new Error("trust refresh unavailable");
    }
    if (!["disabled", "unchanged", "updated"].includes(outcome))
      throw new Error("trust refresh unavailable");
  },
};
export default handler;
