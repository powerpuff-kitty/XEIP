// Real Keycloak + PostgreSQL + signed HTTPS + independent official MCP server.
// Every dependency is an owned disposable loopback fixture; no operator credentials.
import { withKeycloak } from "./keycloak.mjs";
import { withPostgres } from "./postgres.mjs";
import { verifyOrganizationService } from "./organization-service-cases.mjs";
await withKeycloak(async (keycloak) => {
  await withPostgres(async ({ pool }) =>
    verifyOrganizationService({ pool, keycloak }),
  );
});
