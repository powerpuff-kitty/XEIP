import { writeFileSync } from "node:fs";
import { withKeycloak } from "./keycloak.mjs";
import { withPostgres } from "./postgres.mjs";
import { verifyOrganizationService } from "./organization-service-cases.mjs";
await withKeycloak(
  async (keycloak) => {
    await withPostgres(async ({ pool }) => {
      await verifyOrganizationService({pool,keycloak});
      const report = await verifyOrganizationService({
        pool,
        keycloak,
        load: true,
      });
      if (process.env.XEIP_LOAD_REPORT)
        writeFileSync(
          process.env.XEIP_LOAD_REPORT,
          JSON.stringify(report, null, 2) + "\n",
          { mode: 0o600 },
        );
      console.log(JSON.stringify(report, null, 2));
      if (!report.passed) process.exitCode = 1;
    });
  },
  { population: true },
);
