# Experimental local artifact; publication requires a reviewed clean commit.
FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402 AS base
# Signed Alpine security revisions; fail if an exact version is unavailable.
# This updates shared libraries, not Node's independently bundled OpenSSL.
RUN apk add --no-cache 'zlib=1.3.2-r1' 'libcrypto3=3.5.9-r0' 'libssl3=3.5.9-r0'

FROM base AS build
WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY sdks/typescript/src/ sdks/typescript/src/
COPY sdks/typescript/tsconfig.json sdks/typescript/tsconfig.json
RUN npm run build:ts
COPY services/organization/console/ services/organization/console/
RUN node services/organization/console/build.mjs

FROM base AS assemble
WORKDIR /opt/xeip
COPY package.json package-lock.json LICENSE ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund
# Preserve the source manifests; inventory only the installed production graph.
# npm's omit selector can otherwise exclude dependencies shared with dev tools.
RUN node --input-type=module -e '\
  import {readFileSync,writeFileSync,copyFileSync} from "node:fs"; \
  for (const file of ["package.json","package-lock.json"]) { \
    copyFileSync(file,"source."+file); \
    const value=JSON.parse(readFileSync(file,"utf8")); \
    const root=file==="package.json"?value:value.packages[""]; \
    delete root.devDependencies; delete root.scripts; \
    if (value.packages) value.packages=Object.fromEntries(Object.entries(value.packages).filter(([,p])=>!p.dev)); \
    writeFileSync(file,JSON.stringify(value,null,2)+"\n"); \
  }'
RUN npm sbom --package-lock-only --sbom-format=cyclonedx > sbom.cdx.json
COPY --from=build /build/sdks/typescript/dist/ sdks/typescript/dist/
COPY --from=build /build/dist/console/ dist/console/
COPY services/organization/actions.mjs \
     services/organization/auth.mjs \
     services/organization/authorization.mjs \
     services/organization/configuration.mjs \
     services/organization/console-server.mjs \
     services/organization/controller.mjs \
     services/organization/control-state.mjs \
     services/organization/control-store.mjs services/organization/control-lease.mjs \
     services/organization/control-maintenance.mjs services/organization/legacy-checkpoint.mjs \
     services/organization/control-preparation.mjs \
     services/organization/control-preparation-worker.mjs \
     services/organization/database.mjs \
     services/organization/errors.mjs \
     services/organization/execution.mjs \
     services/organization/http.mjs \
     services/organization/lifecycle.mjs \
     services/organization/main.mjs \
     services/organization/maintenance.mjs \
     services/organization/management.mjs \
     services/organization/mcp.mjs \
     services/organization/protected-functions.mjs \
     services/organization/postgres-trust.mjs \
     services/organization/runtime.mjs \
     services/organization/schema.mjs \
     services/organization/store.mjs \
     services/organization/transactions.mjs \
     services/organization/telemetry.mjs services/organization/
COPY services/organization/migrations/ services/organization/migrations/
COPY services/relay/entity-trust.mjs services/relay/trust-checkpoint.mjs services/relay/
COPY packages/identity/entity-envelope.mjs packages/identity/trust-state.mjs \
     packages/identity/key-id.mjs packages/identity/signed-envelope.mjs \
     packages/identity/key-document.mjs packages/identity/identity-status.mjs \
     packages/identity/trust-preparation.mjs packages/identity/trust-preparation-worker.mjs packages/identity/
RUN find . -type f ! -name files.sha256 -print0 | sort -z | xargs -0 sha256sum > files.sha256

FROM base AS runtime
# Build-time package managers are unnecessary in the immutable runtime.
RUN rm -rf /usr/local/lib/node_modules /opt/yarn-* \
    && rm -f /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
             /usr/local/bin/yarn /usr/local/bin/yarnpkg /usr/local/bin/pnpm /usr/local/bin/pnpx
ENV NODE_ENV=production
WORKDIR /opt/xeip
COPY --from=assemble /opt/xeip/ ./
RUN chmod -R a-w /opt/xeip && mkdir -p /var/lib/xeip && chown 1000:1000 /var/lib/xeip && chmod 700 /var/lib/xeip
USER 1000:1000
EXPOSE 8443
STOPSIGNAL SIGTERM
ENTRYPOINT ["node", "services/organization/main.mjs"]
CMD ["serve", "--config", "/etc/xeip/organization.json"]
