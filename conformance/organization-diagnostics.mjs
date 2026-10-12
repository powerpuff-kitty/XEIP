// Fixture-only measurements. Names are supplied by the harness, never by requests.
import { monitorEventLoopDelay } from "node:perf_hooks";

export class LoadDiagnostics {
  #stages = new Map();
  #delay = monitorEventLoopDelay({ resolution: 20 });
  #cpu;
  #started;
  start() {
    this.#stages.clear();
    this.#cpu = process.cpuUsage();
    this.#started = performance.now();
    this.#delay.enable();
  }
  record(name, started, failed = false) {
    if (this.#started === undefined) return;
    const stage = this.#stages.get(name) ?? {
      samples: [],
      failed: 0,
      calls: 0,
    };
    stage.calls++;
    stage.failed += Number(failed);
    if (stage.samples.length < 50000)
      stage.samples.push(performance.now() - started);
    this.#stages.set(name, stage);
  }
  async async(name, work) {
    const started = performance.now();
    let failed = false;
    try {
      return await work();
    } catch (error) {
      failed = true;
      throw error;
    } finally {
      this.record(name, started, failed);
    }
  }
  sync(name, work) {
    const started = performance.now();
    let failed = false;
    try {
      return work();
    } catch (error) {
      failed = true;
      throw error;
    } finally {
      this.record(name, started, failed);
    }
  }
  finish() {
    this.#delay.disable();
    const cpu = process.cpuUsage(this.#cpu);
    const stages = Object.fromEntries(
      [...this.#stages].map(([name, stage]) => {
        const values = stage.samples.toSorted((a, b) => a - b);
        const percentile = (p) =>
          values[Math.max(0, Math.ceil(values.length * p) - 1)] ?? null;
        return [
          name,
          {
            calls: stage.calls,
            failed: stage.failed,
            samples: values.length,
            p50Ms: percentile(0.5),
            p95Ms: percentile(0.95),
            maxMs: values.at(-1) ?? null,
          },
        ];
      }),
    );
    return {
      elapsedMs: performance.now() - this.#started,
      cpuUserMs: cpu.user / 1000,
      cpuSystemMs: cpu.system / 1000,
      eventLoopP95Ms: this.#delay.percentile(95) / 1e6,
      eventLoopMaxMs: this.#delay.max / 1e6,
      stages,
      note: "Inclusive overlapping stage timings; CPU/event-loop refer to the shared Node harness and service, not provider/database containers.",
    };
  }
}
