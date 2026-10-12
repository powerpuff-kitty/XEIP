# Organization capacity investigation and repair

Continue the authorized production-readiness work after runtime review fixes. Target remains 500 users, 200 agents, 120 requested actions/minute and each machine-operation P95 ≤2 seconds. Human thinking is excluded. Baseline: [failed attempt four](../audits/2026-10-11-capacity-attempt-four.md).

- [~] Add bounded fixture-only stage timings and event-loop/CPU observations, distinguish requested/dispatched/completed actions, and run a diagnostic workload with the same limits.
- [ ] Use measurements to select the dominant causal group; document and test the behavior-preserving change before implementation.
- [ ] Rerun the same workload and relevant revocation/recovery regressions; preserve failures and environment limitations.
- [ ] Perform one fresh-context review of the selected implementation, fix Important findings once, and update readiness without substituting local evidence for the operator pilot.

Ruling: do not cache away live authorization or relax deadlines/latency targets to make a benchmark pass. Token acquisition and fixture signing remain explicitly excluded from per-operation latency but consume measured shared resources. Cost: capacity may require more efficient implementation and appropriately provisioned identity infrastructure.

Initial isolated probe on the same host: creating 700 identities took 3.5 seconds, initial trust validation 6.7 seconds, and synchronous signed trust refresh 5.8 seconds. These operations block the Node event loop; the separate probe does not yet assign the full end-to-end failure to refresh. Provider and database waits remain unmeasured.

Environment investigation: the diagnostic run is native amd64, but the host reports load averages 410.75/296.28/298.77 on 8 CPUs; Docker is assigned 8 CPUs and approximately 4 GiB total memory. Timings under this contention are not dedicated-machine capacity. Add wall-versus-process-CPU evidence before attributing long synchronous work entirely to algorithm cost. Do not kill unrelated processes or resize their resources. A reserved-resource acceptance run remains external to this local fixture.

Fixture reporting correction: a new test reproduces the missing requested/dispatched/failed counters on the pre-change code (undefined instead of 600); the corrected harness passes with an injected clock in 27 ms. Ruling: the original RED subprocess unintentionally used its real five-minute schedule while the instrumented version was developed; its later actual failing output is retained at `/tmp/xeip-load-counters-red.log`, so do not claim that assertion was observed before editing. The baseline JSON had already demonstrated the misleading scheduled count. Cost: weaker TDD ordering for fixture reporting, not a changed production authorization path.

Attempt five runs the same selected workload and resource limits with fixture-only inclusive stage timers (provider token acquisition, authenticate/revalidate, database acquisition/query, trust verify/allows/update, client signing, MCP call), Node CPU and event-loop measurements. Successful operations alone supply latency percentiles; failures independently disqualify a run. No behavioral optimization has been applied.

The user selected a dedicated Linux staging host with reserved resources for final capacity/recovery acceptance. Local diagnostics remain preliminary. A second 700-identity probe measured refresh wall time 18.94 seconds versus process CPU 1.90 seconds, demonstrating severe scheduling interference; initial trust was 15.44 seconds wall versus 1.85 seconds CPU.

Attempt five did not reach measurement: Keycloak remained running without OOM but failed its 15-minute startup readiness deadline while host load rose above 600. The owned fixture container and temporary credentials were cleaned up. Preserve `/tmp/xeip-organization-capacity-fifth.log`; no latency or throughput result exists for this attempt. Do not retry capacity on this host until resources are reserved; continue independent artifact/human/recovery work. The performance gate remains open, not silently passed or declared a code-only failure.

Hosting follow-up: the user has no reserved host and selected Cloudflare-native exploration. See [feasibility assessment](../audits/2026-10-11-cloudflare-feasibility.md). Keep the Linux diagnostic evidence and unchanged acceptance targets; a future Workers profile needs its own hosted load/recovery evidence and cannot inherit a pass from these fixtures.

Follow-up: [asynchronous Node trust refresh](identity-async-refresh.md) isolates the measured preparation CPU from request handling while keeping live authorization and parent-owned checkpoint commits. The local 700-identity probe shows timer responsiveness improves; it does not replace the failed/unfinished full workload attempts or the requirement for reserved hosted resources. The capacity fixture now uses the async path so its next authorized acceptance run will measure the launcher mechanism.
