/** TEST ONLY: independent local journal runtime for production Worker outbound mapping. */
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { harness } from "./lifecycle-harness.mjs";
export async function recoveryJournal(t, organization) {
  const runtime = await harness({
    entryPoint: new URL(
      "../../organization-cloudflare-recovery-http-worker.mjs",
      import.meta.url,
    ).pathname,
    className: "RecoveryHttpJournalFixture",
  });
  t.after(() => runtime.close());
  const journal = await runtime.fixture(),
    token = "a1".repeat(32);
  const recovery = {
    url: "https://journal.example/v1/recovery",
    stream: randomUUID(),
    timeoutMs: 10000,
  };
  const { url, ...publicOptions } = recovery,
    options = { ...publicOptions, organization };
  assert.equal(
    (await journal.send({ operation: "initialize", options })).status,
    200,
  );
  assert.equal(
    (await journal.send({ operation: "configureHttp", options })).status,
    200,
  );
  const faults = { unavailable: false, loseAppend: false },
    requests = [];
  return {
    recovery,
    options,
    token,
    journal,
    faults,
    requests,
    async outbound(request) {
      assert.equal(request.url, recovery.url);
      const input = await request.clone().json();
      requests.push(input.operation);
      if (faults.unavailable)
        return Response.json({ error: "unavailable" }, { status: 503 });
      const forwarded = await journal.send({
        operation: "forwardHttp",
        request: {
          url: request.url,
          method: request.method,
          headers: [...request.headers],
          body: await request.text(),
        },
      });
      assert.equal(forwarded.status, 200);
      const response = new Response(forwarded.body.body, {
        status: forwarded.body.status,
        headers: forwarded.body.headers,
      });
      if (input.operation === "append" && faults.loseAppend) {
        void response.body?.cancel();
        return Response.json({ error: "unavailable" }, { status: 503 });
      }
      return response;
    },
    async rotate(nextToken) {
      assert.equal(
        (
          await journal.send({
            operation: "configureHttp",
            options,
            token: nextToken,
          })
        ).status,
        200,
      );
    },
  };
}
