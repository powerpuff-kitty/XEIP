/** Disposable real Keycloak + real local workerd; no deployed API or real tool effect. */
import assert from "node:assert/strict";
import { withKeycloak } from "./keycloak.mjs";
import {
  harness,
  identity,
  configuration,
  provisioning,
  command,
} from "./fixtures/cloudflare/authority-harness.mjs";
await withKeycloak(async (provider) => {
  const runtime = await harness();
  try {
    const actors = [
        identity(provider.subjects.agent),
        identity(provider.subjects.human),
      ],
      config = configuration(provider, actors),
      f = await runtime.fixture();
    assert.equal(
      (
        await f.send({
          operation: "open",
          gateway: actors[0].entity,
          initializeTrust: true,
          provisioning: provisioning(actors),
          configuration: config,
          secret: provider.config.introspectionClientSecret,
        })
      ).body.state,
      "ready",
    );
    const agentToken = await provider.token("agent"),
      humanToken = await provider.token("human");
    const send = (actor, bearer, operation, digest) =>
      f.send({
        operation: "controller",
        header: "Bearer " + bearer,
        envelope: command(
          actor,
          actors[0].entity,
          operation,
          "keycloak",
          digest,
        ),
      });
    const proposed = await send(actors[0], agentToken, "propose");
    assert.equal(proposed.body.state, "pending", JSON.stringify(proposed));
    const digest = proposed.body.proposal.digest;
    assert.equal(
      (await send(actors[1], humanToken, "approve", digest)).body.state,
      "approved",
    );
    assert.equal(
      (await send(actors[0], agentToken, "execute", digest)).body.state,
      "succeeded",
    );
    assert.equal((await f.send({ operation: "controls" })).body.effects, 1);
    assert.equal(
      (
        await f.send({
          operation: "authenticate",
          header: "Bearer " + agentToken,
        })
      ).body.principal.subject,
      actors[0].subject,
    );
    assert.equal(
      (await f.send({ operation: "revalidate" })).body.allowed,
      true,
    );
    await provider.revoke(agentToken);
    assert.equal(
      (await f.send({ operation: "revalidate" })).body.allowed,
      false,
    );
    assert.equal(
      (await send(actors[0], agentToken, "inspect")).body.status,
      401,
    );
    assert.equal((await f.send({ operation: "controls" })).body.effects, 1);
    console.log(
      "PASS real Keycloak/workerd: signed propose, separate-subject approval, one claimed effect, durable outcome and live token revocation",
    );
    console.log(
      "Approver token uses fixture client credentials; human PKCE/browser acceptance remains open.",
    );
  } finally {
    await runtime.close();
  }
});
