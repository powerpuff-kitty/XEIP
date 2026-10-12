import test from "node:test";
import assert from "node:assert/strict";
import { request } from "node:https";
import { readFileSync } from "node:fs";
import { createManagementServer } from "./management.mjs";
const tls = {
  cert: readFileSync(new URL("./test-fixtures/tls/cert.pem", import.meta.url)),
  key: readFileSync(new URL("./test-fixtures/tls/key.pem", import.meta.url)),
};
test("metrics require loopback TLS, exact bearer and safe method/host/origin", async (t) => {
  const token = "a".repeat(48);
  let reads = 0;
  const server = createManagementServer({
    tls,
    host: "127.0.0.1",
    origin: "https://xeip.test",
    token,
    metrics: () => {
      reads++;
      return "xeip_ready 1\n";
    },
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(
    () =>
      new Promise((resolve) => {
        server.closeAllConnections();
        server.close(resolve);
      }),
  );
  const send = (headers = {}, path = "/metrics", method = "GET") =>
    new Promise((resolve, reject) => {
      const req = request(
        {
          host: "127.0.0.1",
          port: server.address().port,
          servername: "xeip.test",
          ca: tls.cert,
          path,
          method,
          headers: { Authorization: "Bearer " + token, ...headers },
        },
        (res) => {
          let body = "";
          res.on("data", (part) => (body += part));
          res.on("end", () => resolve({ status: res.statusCode, body }));
        },
      );
      req.on("error", reject);
      req.end();
    });
  assert.deepEqual(await send(), { status: 200, body: "xeip_ready 1\n" });
  for (const headers of [
    { Authorization: "Bearer wrong" },
    { Host: "evil.test" },
    { Origin: "https://xeip.test" },
    { Authorization: ["Bearer " + token, "Bearer " + token] },
  ])
    assert.notEqual((await send(headers)).status, 200);
  assert.equal((await send({}, "/metrics?token=secret")).status, 404);
  assert.equal((await send({}, "/metrics", "POST")).status, 405);
  assert.equal(reads, 1);
  assert.throws(() =>
    createManagementServer({
      tls,
      host: "0.0.0.0",
      origin: "https://xeip.test",
      token,
      metrics: () => "",
    }),
  );
});
