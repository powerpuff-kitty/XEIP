// Full signed HTTPS path, real PostgreSQL and official MCP server, local RSA/OAuth fixture.
import assert from "node:assert/strict";
import { randomBytes, createPublicKey, randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { measureOrganizationLoad } from "./organization-load.mjs";
import { LoadDiagnostics } from "./organization-diagnostics.mjs";
import { request as httpsRequest } from "node:https";
import { fixture } from "../services/organization/test-fixtures/provider.mjs";
import { mcpFixture } from "../services/organization/test-fixtures/mcp.mjs";
import { encodeKeyId } from "../tools/derive-keyid.mjs";
import { ed25519PrivateKeyFromSeed } from "../tools/signed-envelope.mjs";
import { signKeyDocument } from "../tools/key-document.mjs";
import { signStatusDocument } from "../tools/identity-status.mjs";
import { signEntityEnvelope } from "../packages/identity/entity-envelope.mjs";
import { EntityTrustPolicy } from "../services/relay/entity-trust.mjs";
import { KeycloakAuthenticator } from "../services/organization/auth.mjs";
import { ActionPolicy } from "../services/organization/actions.mjs";
import { ActionStore } from "../services/organization/store.mjs";
import { OrganizationController } from "../services/organization/controller.mjs";
import { createOrganizationServer } from "../services/organization/http.mjs";
import { createActionExecutor } from "../services/organization/execution.mjs";
import { McpConnector } from "../services/organization/mcp.mjs";
const utc = (seconds) =>
  new Date(seconds * 1000).toISOString().replace(".000Z", "Z");
function identity(subject) {
  const seed = randomBytes(32),
    kid = encodeKeyId(
      createPublicKey(ed25519PrivateKeyFromSeed(seed))
        .export({ format: "der", type: "spki" })
        .subarray(-32),
    ),
    entity = "urn:xeip:entity:" + kid;
  const now = Math.floor(Date.now() / 1000),
    issuedAt = utc(now);
  const document = signKeyDocument(
    {
      xeip: "xeip.keydoc/0.1",
      entity,
      genesis: kid,
      generation: 1,
      issuedAt,
      roots: [kid],
      devices: [],
      signatures: [],
    },
    { privateKey: seed, kid },
  );
  const status = (serial) => ({
    document: signStatusDocument(
      {
        xeip: "xeip.status/0.1",
        entity,
        serial,
        issuedAt: utc(Math.floor(Date.now() / 1000)),
        revoked: [],
        signatures: [],
      },
      { privateKey: seed, kid },
    ),
  });
  return {
    subject,
    seed,
    kid,
    entity,
    keyDocument: { document, anchor: { genesisKid: kid } },
    status,
  };
}
export async function verifyOrganizationService({
  pool,
  keycloak,
  load = false,
}) {
  const cleanup = [],
    t = { after: (fn) => cleanup.push(fn) };
  try {
    const diagnostics = new LoadDiagnostics();
    const agents = (
      load
        ? keycloak.subjects.agents
        : [keycloak?.subjects.agent ?? "service-agent"]
    ).map((subject, index) => ({ ...identity(subject), role: "agent", index }));
    const humans = (
      load
        ? keycloak.subjects.humans
        : [keycloak?.subjects.human ?? "service-human"]
    ).map((subject, index) => ({ ...identity(subject), role: "human", index }));
    const all = [...agents, ...humans],
      agent = agents[0],
      human = humans[0],
      session = "urn:test:service:" + randomUUID();
    const upstream = await mcpFixture(t),
      provider = keycloak ?? (await fixture(t));
    let lastAgentToken;
    const auth = new KeycloakAuthenticator({
      ...provider.config,
      bindings: all.map(({ subject, entity, kid }) => ({
        subject,
        entity,
        kid,
      })),
    });
    if (load)
      for (const method of ["authenticate", "revalidate"]) {
        const original = auth[method].bind(auth);
        auth[method] = (...args) =>
          diagnostics.async("auth." + method, () => original(...args));
      }
    const policy = new ActionPolicy({
      targets: [
        {
          id: upstream.config.id,
          revision: upstream.config.revision,
          recipient: upstream.config.recipient,
          tools: upstream.config.tools,
        },
      ],
      sessions: [
        {
          id: session,
          agents: agents.map((actor) => actor.subject),
          approvers: humans.map((actor) => actor.subject),
          targets: ["internal"],
        },
      ],
    });
    const directory = mkdtempSync(join(tmpdir(), "xeip-service-"));
    const trust = new EntityTrustPolicy(
      { trustDir: join(directory, "trust"), maxAgeSeconds: 180 },
      all.map((actor) => actor.keyDocument),
      all.map((actor) => actor.status(1)),
    );
    if (load)
      for (const method of ["verify", "allows"]) {
        const original = trust[method].bind(trust);
        trust[method] = (...args) =>
          diagnostics.sync("trust." + method, () => original(...args));
      }
    if (load) {
      const update = trust.updateAsync.bind(trust);
      trust.updateAsync = (...args) =>
        diagnostics.async("trust.update", () => update(...args));
    }
    t.after(() => {
      trust.close();
      rmSync(directory, { recursive: true, force: true });
    });
    let lostCompletion = false;
    const database = {
      options: pool.options,
      connect: async () => {
        const client = await diagnostics.async("database.acquire", () =>
          pool.connect(),
        );
        let finishing = false;
        return {
          release: (broken) => client.release(broken),
          on: (...args) => client.on(...args),
          removeListener: (...args) => client.removeListener(...args),
          query: async (...args) => {
            if (
              typeof args[0] === "string" &&
              args[0].includes("result_canonical=$4")
            )
              finishing = true;
            const result = await diagnostics.async("database.query", () =>
              client.query(...args),
            );
            if (lostCompletion && finishing && args[0] === "COMMIT") {
              lostCompletion = false;
              throw new Error("fixture lost completion acknowledgement");
            }
            return result;
          },
        };
      },
    };
    const connector = new McpConnector([upstream.config]);
    if (load) {
      const call = connector.call.bind(connector);
      connector.call = (...args) =>
        diagnostics.async("mcp.call", () => call(...args));
    }
    const controller = new OrganizationController({
      authentication: auth,
      trust,
      gateway: upstream.config.recipient,
      createStore: (authorize) => new ActionStore(database, policy, authorize),
      execute: createActionExecutor(policy, connector),
    });
    const tls = {
      key: readFileSync(
        new URL(
          "../services/organization/test-fixtures/tls/key.pem",
          import.meta.url,
        ),
      ),
      cert: readFileSync(
        new URL(
          "../services/organization/test-fixtures/tls/cert.pem",
          import.meta.url,
        ),
      ),
    };
    const server = createOrganizationServer({
      controller,
      origin: "https://xeip.test",
      tls,
      ready: async () => {
        await pool.query("SELECT 1");
        return true;
      },
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    t.after(async () => {
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    });
    async function send(actor, operation, id, digest, edit) {
      const now = Math.floor(Date.now() / 1000),
        request = {
          id,
          session,
          target: "internal",
          tool: "lookup",
          arguments: { query: "approved " + id },
          expiresAt: now + 120,
        };
      const envelope = {
        xeip: "0.1",
        id: operation === "propose" ? id : "urn:test:op:" + randomUUID(),
        kind: "command",
        sender: actor.entity,
        recipient: upstream.config.recipient,
        session,
        timestamp: utc(now),
        expiresAt: utc(now + 60),
        body: {
          contentType: "application/vnd.xeip.organization-action+json",
          data:
            operation === "propose"
              ? { operation, request }
              : {
                  operation,
                  session,
                  id,
                  ...(operation === "inspect" ? {} : { digest }),
                },
        },
      };
      const signed = diagnostics.sync("client.sign", () =>
        signEntityEnvelope(envelope, {
          privateKey: actor.seed,
          kid: actor.kid,
        }),
      );
      if (edit) edit(signed);
      const token = keycloak
        ? await diagnostics.async("client.token", () =>
            keycloak.token(actor.role, actor.index),
          )
        : await provider.token({
            sub: actor.subject,
            jti: randomUUID(),
            azp: actor === agent ? "xeip-agent" : "xeip-console",
            resource_access: {
              "xeip-api": { roles: actor === agent ? ["agent"] : ["approver"] },
            },
          });
      if (actor === agent) lastAgentToken = token;
      const started = performance.now();
      return new Promise((resolve, reject) => {
        const req = httpsRequest(
          {
            host: "127.0.0.1",
            port: server.address().port,
            path: "/v1/actions",
            method: "POST",
            ca: tls.cert,
            signal: AbortSignal.timeout(60000),
            headers: {
              Host: "xeip.test",
              "Content-Type": "application/json",
              Authorization: "Bearer " + token,
            },
          },
          (res) => {
            let data = "";
            res.on("data", (part) => (data += part));
            res.on("end", () =>
              resolve({
                status: res.statusCode,
                latencyMs: performance.now() - started,
                ...JSON.parse(data),
              }),
            );
          },
        );
        req.on("error", reject);
        req.end(JSON.stringify(signed));
      });
    }
    if (load) {
      let serial = 1;
      let refreshing;
      const refresh = setInterval(() => {
        if (refreshing) return;
        refreshing = diagnostics
          .async("fixture.refresh", () =>
            trust.updateAsync({
              keyDocuments: all.map((actor) => actor.keyDocument),
              statusDocuments: all.map((actor) => actor.status(++serial)),
            }),
          )
          .catch(() => trust.close())
          .finally(() => {
            refreshing = undefined;
          });
      }, 60000);
      t.after(async () => {
        clearInterval(refresh);
        await refreshing;
      });
      diagnostics.start();
      const report = await measureOrganizationLoad({ agents, humans, send });
      report.diagnostics = diagnostics.finish();
      return report;
    }
    async function approved(label) {
      const id = "urn:test:" + label + ":" + randomUUID(),
        proposal = await send(agent, "propose", id);
      assert.equal(proposal.status, 200);
      assert.equal(proposal.state, "pending");
      assert.equal(Object.hasOwn(proposal, "claimId"), false);
      const digest = proposal.proposal.digest;
      assert.equal(
        (await send(human, "approve", id, digest)).state,
        "approved",
      );
      return { id, digest };
    }
    const first = await approved("success");
    assert.equal(
      (await send(agent, "approve", first.id, first.digest)).status,
      403,
    );
    assert.equal(
      (await send(agent, "execute", first.id, "0".repeat(64))).status,
      409,
    );
    assert.equal(
      (
        await send(
          agent,
          "execute",
          first.id,
          first.digest,
          (e) => (e.recipient = agent.entity),
        )
      ).status,
      403,
    );
    assert.equal(upstream.state.calls.length, 0);
    const results = await Promise.all(
      Array.from({ length: 6 }, () =>
        send(agent, "execute", first.id, first.digest),
      ),
    );
    assert.equal(results.filter((r) => r.state === "succeeded").length, 1);
    assert.equal(results.filter((r) => r.status === 409).length, 5);
    assert.equal(upstream.state.calls.length, 1);
    const history = await send(human, "inspect", first.id);
    assert.equal(history.state, "succeeded");
    assert.equal(history.result.content[0].text, "fixture result");
    assert.equal(Object.hasOwn(history, "claimId"), false);
    console.log(
      "PASS signed HTTPS service: bearer/entity binding, exact approval, concurrent single effect, durable result inspection",
    );
    const revoked = await approved("revoke");
    assert.equal(
      (await send(human, "revoke", revoked.id, revoked.digest)).state,
      "revoked",
    );
    assert.equal(
      (await send(agent, "execute", revoked.id, revoked.digest)).status,
      409,
    );
    assert.equal(upstream.state.calls.length, 1);
    const expiredIdentity = await approved("identity");
    // Authentication + claim pass; the final provider check before the tool POST denies.
    upstream.state.beforeGrant = async () => {
      if (keycloak) await keycloak.revoke(lastAgentToken);
      else provider.state.active = false;
    };
    assert.equal(
      (await send(agent, "execute", expiredIdentity.id, expiredIdentity.digest))
        .state,
      "failed",
    );
    assert.equal(upstream.state.calls.length, 1);
    upstream.state.beforeGrant = null;
    if (!keycloak) provider.state.active = true;
    console.log(
      "PASS signed HTTPS service: explicit revocation and identity deactivation after claim prevent effects",
    );
    for (const mode of ["disconnect", "oversize"]) {
      const action = await approved(mode);
      upstream.state.mode = mode;
      assert.equal(
        (await send(agent, "execute", action.id, action.digest)).state,
        "indeterminate",
      );
      assert.equal(
        (await send(agent, "execute", action.id, action.digest)).status,
        409,
      );
      upstream.state.mode = "ok";
    }
    const uncertain = await approved("lost-completion");
    lostCompletion = true;
    assert.equal(
      (await send(agent, "execute", uncertain.id, uncertain.digest)).status,
      503,
    );
    const recovered = await send(agent, "inspect", uncertain.id);
    assert.equal(recovered.state, "succeeded");
    assert.equal(recovered.result.content[0].text, "fixture result");
    assert.equal(
      (await send(agent, "execute", uncertain.id, uncertain.digest)).status,
      409,
    );
    assert.equal(upstream.state.calls.length, 4);
    console.log(
      "PASS signed HTTPS service: ambiguous upstream and completion persistence cannot replay; committed result resolves lost response",
    );
  } finally {
    for (const fn of cleanup.reverse()) await fn();
  }
}
