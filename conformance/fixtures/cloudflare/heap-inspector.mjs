/** TEST ONLY: read local workerd isolate memory; never connect to a remote inspector. */
import assert from "node:assert/strict";
export async function heapInspector(address, worker) {
  const base = new URL(address);
  assert.equal(base.protocol, "ws:");
  assert.equal(base.hostname, "127.0.0.1");
  const endpoint = new URL("/json/list", base);
  endpoint.protocol = "http:";
  const response = await fetch(endpoint, {
    signal: AbortSignal.timeout(10000),
  });
  assert.equal(response.ok, true);
  const targets = (await response.json()).filter(
    (t) => t.id === `core:user:${worker}`,
  );
  assert.equal(targets.length, 1);
  const socketURL = new URL(targets[0].webSocketDebuggerUrl);
  assert.equal(socketURL.protocol, "ws:");
  assert.equal(socketURL.hostname, base.hostname);
  assert.equal(socketURL.port, base.port);
  const socket = new WebSocket(socketURL);
  const pending = new Map();
  let next = 0;
  const fail = () => {
    for (const p of pending.values()) p.reject(Error("local inspector closed"));
    pending.clear();
  };
  socket.addEventListener("error", fail);
  socket.addEventListener("close", fail);
  socket.addEventListener("message", ({ data }) => {
    const message = JSON.parse(data);
    if (!message.id) return;
    const p = pending.get(message.id);
    if (!p) return;
    pending.delete(message.id);
    if (message.error) p.reject(Error("local inspector command failed"));
    else p.resolve(message.result);
  });
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => reject(Error("local inspector connection timeout")),
        10000,
      );
      socket.addEventListener(
        "open",
        () => {
          clearTimeout(timer);
          resolve();
        },
        { once: true },
      );
      socket.addEventListener(
        "error",
        () => {
          clearTimeout(timer);
          reject(Error("local inspector connection failed"));
        },
        { once: true },
      );
    });
  } catch (error) {
    socket.close();
    throw error;
  }
  function request(method, params = {}) {
    return new Promise((resolve, reject) => {
      const id = ++next;
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(Error("local inspector request timeout"));
      }, 10000);
      pending.set(id, {
        resolve(value) {
          clearTimeout(timer);
          resolve(value);
        },
        reject(error) {
          clearTimeout(timer);
          reject(error);
        },
      });
      socket.send(JSON.stringify({ id, method, params }));
    });
  }
  return {
    async startHeapProfile() {
      await request("HeapProfiler.enable");
      await request("HeapProfiler.startSampling", {
        samplingInterval: 32768,
        includeObjectsCollectedByMajorGC: true,
        includeObjectsCollectedByMinorGC: true,
      });
    },
    async stopHeapProfile() {
      const result = await request("HeapProfiler.stopSampling");
      let profilerDisabled = false;
      try {
        await request("HeapProfiler.disable");
        profilerDisabled = true;
      } catch {
        // Preserve an acquired profile; runtime teardown ends inspection.
      }
      return { profile: result.profile, profilerDisabled };
    },
    async startCpuProfile() {
      await request("Profiler.enable");
      await request("Profiler.setSamplingInterval", { interval: 1000 });
      await request("Profiler.start");
    },
    async stopCpuProfile() {
      const result = await request("Profiler.stop");
      let profilerDisabled = false;
      try {
        await request("Profiler.disable");
        profilerDisabled = true;
      } catch {
        // Preserve an acquired profile; runtime teardown ends inspection.
      }
      return { profile: result.profile, profilerDisabled };
    },
    async usage() {
      const result = await request("Runtime.getHeapUsage");
      for (const key of [
        "usedSize",
        "totalSize",
        "embedderHeapUsedSize",
        "backingStorageSize",
      ])
        assert.ok(Number.isSafeInteger(result[key]) && result[key] >= 0, key);
      return result;
    },
    close() {
      fail();
      socket.close();
    },
  };
}
