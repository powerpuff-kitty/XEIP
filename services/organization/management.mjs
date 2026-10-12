import { createServer } from "node:https";
import { createHash, timingSafeEqual } from "node:crypto";
/** @param {{tls:{key:string|Buffer,cert:string|Buffer},host:string,origin:string,token:string,metrics:()=>string}} configuration */
export function createManagementServer({ tls, host, origin, token, metrics }) {
  if (
    !["127.0.0.1", "::1"].includes(host) ||
    typeof token !== "string" ||
    token.length < 32 ||
    token.length > 4096 ||
    typeof metrics !== "function"
  )
    throw new TypeError("invalid management configuration");
  const expected = createHash("sha256")
    .update("Bearer " + token)
    .digest();
  const publicHost = new URL(origin).hostname;
  const server = createServer(
    { ...tls, minVersion: "TLSv1.2", maxHeaderSize: 8192 },
    (request, response) => {
      let status = 200;
      const address = server.address();
      const port = address && typeof address === "object" ? address.port : 0;
      const hosts = [
        `${host === "::1" ? "[::1]" : host}:${port}`,
        `${publicHost}:${port}`,
      ];
      const authorization = request.headers.authorization;
      const duplicate = ["host", "authorization"].some(
        (header) =>
          request.rawHeaders.filter(
            (value, i) => i % 2 === 0 && value.toLowerCase() === header,
          ).length !== 1,
      );
      if (
        !["127.0.0.1", "::1", "::ffff:127.0.0.1"].includes(
          request.socket.remoteAddress ?? "",
        ) ||
        duplicate ||
        !hosts.includes(request.headers.host ?? "") ||
        request.headers.origin !== undefined
      )
        status = 403;
      else if (
        typeof authorization !== "string" ||
        authorization.length > 4103 ||
        !timingSafeEqual(
          expected,
          createHash("sha256").update(authorization).digest(),
        )
      )
        status = 401;
      else if (request.url !== "/metrics") status = 404;
      else if (request.method !== "GET") status = 405;
      else if (
        request.headers["transfer-encoding"] !== undefined ||
        Number(request.headers["content-length"] ?? 0) !== 0
      )
        status = 400;
      let body = "unavailable\n";
      if (status === 200) {
        try {
          body = metrics();
          if (typeof body !== "string" || Buffer.byteLength(body) > 262144)
            throw new Error();
        } catch {
          status = 503;
          body = "unavailable\n";
        }
      }
      response.writeHead(status, {
        "Content-Type": "text/plain; version=0.0.4; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        Connection: "close",
      });
      response.end(body);
    },
  );
  server.maxConnections = 16;
  server.maxHeadersCount = 16;
  server.headersTimeout = 2000;
  server.requestTimeout = 2000;
  server.keepAliveTimeout = 1000;
  return server;
}
