# Capacity attempt four — 11 October 2026

Result: **FAIL**. This is a local fixture, not a deployed organization.

Provisioned 500 simulated approvers and 200 agents; exercised 302 approvers and 200 agents. Requested 600 actions at 120/min; scheduling stopped at the 64-pending limit. Only 11 completed in 201.5 seconds (3.27/min). The original report field `scheduledActions=600` describes the requested count, not the actual dispatched count; the harness needs separate counters.

P95 of successful responses only (failure rate is independently disqualifying):

| Operation | Successful samples | P95 ms |
| --- | ---: | ---: |
| propose | 82 | 25734.4 |
| approve | 54 | 25427.1 |
| execute | 19 | 28043.1 |
| inspect | 11 | 20730.0 |

Failure counts (fixed fixture messages; no credentials):

- propose:503:undefined: 110
- The operation was aborted due to timeout: 57
- propose:429:undefined: 49
- execute:503:undefined: 27
- approve:503:undefined: 23
- inspect:503:undefined: 8
- read ECONNRESET: 3
- approve:429:undefined: 3
- execute:504:undefined: 3
- execute:200:failed: 3
- execute:429:undefined: 2
- propose:504:undefined: 2
- approve:504:undefined: 1
- load concurrency limit: 1

Environment: Node 26.8.1/macOS host; loopback Keycloak 26.8.0 development fixture limited to 2 CPUs/1 GiB; PostgreSQL 18.6 limited to 1 CPU/512 MiB; official MCP SDK 2.3.1 fixture. The Docker host also had unrelated workloads. Human approval was simulated. Token issuance and client signing are excluded from each operation timer but still consume shared fixture resources. No root cause has yet been established.

Next: instrument provider, SQL, trust refresh, signing and event-loop delay; distinguish harness effects from service bottlenecks, then remeasure under equivalent limits. Do not relax the P95 ≤2-second target or live authorization semantics.

Subsequent environment check during diagnostic attempt five: native x86_64 host and amd64 images (no architecture emulation); Docker has 8 CPUs/approximately 4 GiB total memory. Host load averages were **410.75 / 296.28 / 298.77** on **8 CPUs**. This is severe contention evidence measured after attempt four, not a captured measurement during its workload. It prevents assigning the wall-clock failure solely to application code or certifying dedicated-machine capacity. Unrelated workloads are left untouched.
