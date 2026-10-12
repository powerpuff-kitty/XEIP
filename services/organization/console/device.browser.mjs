import { test, expect } from "@playwright/test";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
let server, origin;
test.beforeAll(async () => {
  server = createServer(async (req, res) => {
    const paths = {
      "/device.mjs": new URL("./device.mjs", import.meta.url),
      "/sdks/typescript/dist/identity.js": new URL(
        "../../../sdks/typescript/dist/identity.js",
        import.meta.url,
      ),
    };
    if (req.url === "/") {
      res.setHeader("Content-Type", "text/html");
      res.end("<!doctype html><title>Device fixture</title>");
      return;
    }
    try {
      if (!paths[req.url]) throw Error();
      res.setHeader("Content-Type", "text/javascript");
      res.end(await readFile(paths[req.url]));
    } catch {
      res.statusCode = 404;
      res.end();
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
});
test.afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
});
test.beforeEach(async ({ page }) => {
  await page.goto(origin);
});
test("device creation is explicit and a non-extractable signing key survives reload", async ({
  page,
}) => {
  const first = await page.evaluate(async () => {
    const m = await import("/device.mjs");
    if ((await m.loadDevice("https://id.example/realms/org", "human")) !== null)
      throw Error("implicit creation");
    const device = await m.createDevice(
      "https://id.example/realms/org",
      "human",
    );
    let rejected = false;
    try {
      await crypto.subtle.exportKey("pkcs8", device.privateKey);
    } catch {
      rejected = true;
    }
    return {
      kid: device.kid,
      rejected,
      extractable: device.privateKey.extractable,
    };
  });
  expect(first.rejected).toBe(true);
  expect(first.extractable).toBe(false);
  await page.reload();
  expect(
    await page.evaluate(async () => {
      const m = await import("/device.mjs");
      return (await m.loadDevice("https://id.example/realms/org", "human")).kid;
    }),
  ).toBe(first.kid);
});
test("concurrent creation cannot replace the enrolled key", async ({
  page,
}) => {
  const ids = await page.evaluate(async () => {
    const m = await import("/device.mjs");
    return Promise.all(
      Array.from(
        { length: 8 },
        async () =>
          (await m.createDevice("https://id.example/realms/org", "human")).kid,
      ),
    );
  });
  expect(new Set(ids).size).toBe(1);
});
test("issuer and subject isolate keys without collisions", async ({ page }) => {
  const ids = await page.evaluate(async () => {
    const m = await import("/device.mjs");
    return Promise.all(
      [
        ["https://id.example/realms/org", "human"],
        ["https://id.example/realms/other", "human"],
        ["https://id.example/realms/org", "other"],
      ].map(async ([issuer, sub]) => (await m.createDevice(issuer, sub)).kid),
    );
  });
  expect(new Set(ids).size).toBe(3);
});
test("corrupt persisted key requires recovery and is never replaced", async ({
  page,
}) => {
  const result = await page.evaluate(async () => {
    const m = await import("/device.mjs");
    await m.createDevice("https://id.example/realms/org", "human");
    const db = await new Promise((resolve, reject) => {
      const r = indexedDB.open("xeip-approval-devices", 1);
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
    });
    const namespace = JSON.stringify([
      "https://id.example/realms/org",
      "human",
    ]);
    await new Promise((resolve, reject) => {
      const t = db.transaction("devices", "readwrite");
      t.objectStore("devices").put({ kid: "corrupt" }, namespace);
      t.oncomplete = resolve;
      t.onerror = reject;
    });
    db.close();
    const codes = [];
    for (const operation of [m.loadDevice, m.createDevice]) {
      try {
        await operation("https://id.example/realms/org", "human");
        codes.push("accepted");
      } catch (e) {
        codes.push(e.code);
      }
    }
    return codes;
  });
  expect(result).toEqual(["device_corrupt", "device_corrupt"]);
});
test("a mismatched public/private pair is rejected", async ({ page }) => {
  expect(
    await page.evaluate(async () => {
      const m = await import("/device.mjs");
      const first = await m.createDevice(
        "https://id.example/realms/org",
        "human",
      );
      const second = await m.createDevice(
        "https://id.example/realms/org",
        "other",
      );
      const db = await new Promise((resolve) => {
        const r = indexedDB.open("xeip-approval-devices", 1);
        r.onsuccess = () => resolve(r.result);
      });
      await new Promise((resolve) => {
        const t = db.transaction("devices", "readwrite");
        t.objectStore("devices").put(
          { ...first, privateKey: second.privateKey },
          JSON.stringify(["https://id.example/realms/org", "human"]),
        );
        t.oncomplete = resolve;
      });
      db.close();
      try {
        await m.loadDevice("https://id.example/realms/org", "human");
        return "accepted";
      } catch (e) {
        return e.code;
      }
    }),
  ).toBe("device_corrupt");
});
test("untrusted namespaces are rejected before opening storage", async ({
  page,
}) => {
  const codes = await page.evaluate(async () => {
    const m = await import("/device.mjs");
    return Promise.all(
      [
        ["http://id.example", "human"],
        ["https://id.example/?x=1", "human"],
        ["https://id.example", ""],
        ["https://id.example", "a\u0000b"],
      ].map(async ([issuer, sub]) => {
        try {
          await m.createDevice(issuer, sub);
          return "accepted";
        } catch (e) {
          return e.code;
        }
      }),
    );
  });
  expect(codes).toEqual(Array(4).fill("invalid_identity"));
});
