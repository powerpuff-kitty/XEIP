/** Keycloak authentication only; membership, identity trust and actions are separate gates. */
import { createRemoteJWKSet, customFetch, jwtVerify } from "jose";
import { decodeKeyId } from "../../sdks/typescript/dist/identity.js";

/** @typedef {{subject: string, entity: string, kid: string}} SubjectBinding */
/** @typedef {{issuer: string, audience: string, clientIds: string[], bindings: SubjectBinding[], introspectionClientId: string, introspectionClientSecret: string, allowInsecureLoopback?: boolean, timeoutMs?: number, maxTokenLifetimeSeconds?: number}} AuthConfiguration */
/** @typedef {import('./contracts.js').OrganizationPrincipal} OrganizationPrincipal */
/** @param {unknown} value @returns {value is Record<string, unknown>} */
const object = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);
/** @param {unknown} value @param {number} [max] @returns {value is string} */
const text = (value, max = 256) =>
  typeof value === "string" &&
  value.length > 0 &&
  value.length <= max &&
  !/[\u0000-\u001f\u007f]/.test(value);

export class IdentityProviderUnavailable extends Error {
  constructor() {
    super("identity provider unavailable");
    this.name = "IdentityProviderUnavailable";
  }
}

/** @param {string} url @param {RequestInit} init @param {number} timeoutMs */
async function boundedJsonResponse(url, init, timeoutMs) {
  try {
    const response = await fetch(url, {
      ...init,
      // Workers supports manual/follow only. Require 200 below and never follow
      // redirects, so issuer credentials cannot leave the pinned endpoint.
      redirect: "manual",
      signal: AbortSignal.any([
        AbortSignal.timeout(timeoutMs),
        ...(init.signal ? [init.signal] : []),
      ]),
    });
    if (
      response.status !== 200 ||
      !/^application\/json(?:\s*;|$)/i.test(
        response.headers.get("content-type") ?? "",
      )
    ) {
      await response.body?.cancel();
      throw new IdentityProviderUnavailable();
    }
    if (!response.body) throw new IdentityProviderUnavailable();
    const reader = response.body.getReader();
    /** @type {Uint8Array[]} */
    const chunks = [];
    let length = 0;
    try {
      for (;;) {
        const part = await reader.read();
        if (part.done) break;
        length += part.value.byteLength;
        if (length > 65536) throw new IdentityProviderUnavailable();
        chunks.push(part.value);
      }
    } catch (error) {
      await reader.cancel().catch(() => {});
      throw error;
    } finally {
      reader.releaseLock();
    }
    const body = new TextDecoder("utf-8", { fatal: true }).decode(
      Buffer.concat(chunks),
    );
    JSON.parse(body);
    return new Response(body, {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch {
    throw new IdentityProviderUnavailable();
  }
}

/** @typedef {import('./contracts.js').Authentication} Authentication */
/** @implements {Authentication} */
export class KeycloakAuthenticator {
  #issuer;
  #audience;
  #clients;
  #clientId;
  #secret;
  #timeout;
  #lifetime;
  #jwks;
  /** @type {Map<string, Readonly<SubjectBinding>>} */
  #bindings = new Map();
  /** @type {WeakMap<OrganizationPrincipal, string>} */
  #tokens = new WeakMap();
  /** @param {AuthConfiguration} configuration */
  constructor(configuration) {
    if (
      !object(configuration) ||
      Object.keys(configuration).some(
        (name) =>
          ![
            "issuer",
            "audience",
            "clientIds",
            "bindings",
            "introspectionClientId",
            "introspectionClientSecret",
            "allowInsecureLoopback",
            "timeoutMs",
            "maxTokenLifetimeSeconds",
          ].includes(name),
      )
    )
      throw new TypeError("invalid authentication configuration");
    const {
      issuer,
      audience,
      clientIds,
      bindings,
      introspectionClientId,
      introspectionClientSecret,
      timeoutMs = 3000,
      maxTokenLifetimeSeconds = 300,
      allowInsecureLoopback = false,
    } = configuration;
    if (!text(issuer, 2048)) throw new TypeError("issuer required");
    const url = new URL(issuer);
    if (
      url.href !== issuer ||
      issuer.endsWith("/") ||
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      (url.protocol !== "https:" &&
        !(
          allowInsecureLoopback === true &&
          url.protocol === "http:" &&
          ["127.0.0.1", "[::1]"].includes(url.hostname)
        ))
    )
      throw new TypeError("pinned HTTPS issuer required");
    if (
      !text(audience) ||
      !text(introspectionClientId) ||
      !text(introspectionClientSecret, 4096) ||
      !Array.isArray(clientIds) ||
      !clientIds.length ||
      clientIds.some((client) => !text(client)) ||
      new Set(clientIds).size !== clientIds.length ||
      !Number.isInteger(timeoutMs) ||
      timeoutMs < 100 ||
      timeoutMs > 10000 ||
      !Number.isInteger(maxTokenLifetimeSeconds) ||
      maxTokenLifetimeSeconds < 30 ||
      maxTokenLifetimeSeconds > 900 ||
      typeof allowInsecureLoopback !== "boolean" ||
      !Array.isArray(bindings) ||
      !bindings.length ||
      bindings.length > 10000
    )
      throw new TypeError("invalid authentication configuration");
    for (const binding of bindings) {
      if (
        !object(binding) ||
        Object.keys(binding).sort().join(",") !== "entity,kid,subject" ||
        !text(binding.subject) ||
        !text(binding.entity, 2048) ||
        !binding.entity.startsWith("urn:xeip:entity:") ||
        !text(binding.kid) ||
        this.#bindings.has(binding.subject)
      )
        throw new TypeError("invalid subject binding");
      decodeKeyId(binding.kid);
      this.#bindings.set(
        binding.subject,
        Object.freeze({
          subject: binding.subject,
          entity: binding.entity,
          kid: binding.kid,
        }),
      );
    }
    this.#issuer = issuer;
    this.#audience = audience;
    this.#clients = new Set(clientIds);
    this.#clientId = introspectionClientId;
    this.#secret = introspectionClientSecret;
    this.#timeout = timeoutMs;
    this.#lifetime = maxTokenLifetimeSeconds;
    this.#jwks = createRemoteJWKSet(
      new URL(issuer + "/protocol/openid-connect/certs"),
      {
        timeoutDuration: timeoutMs,
        cooldownDuration: 30000,
        cacheMaxAge: 60000,
        [customFetch]: (resource, options) =>
          boundedJsonResponse(resource, options, this.#timeout),
      },
    );
  }
  /** @param {unknown} header @returns {Promise<OrganizationPrincipal | null>} */
  async authenticate(header) {
    if (
      typeof header !== "string" ||
      !header.startsWith("Bearer ") ||
      header.length > 16391
    )
      return null;
    const token = header.slice(7);
    if (!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token))
      return null;
    let payload;
    const now = Math.floor(Date.now() / 1000);
    try {
      ({ payload } = await jwtVerify(token, this.#jwks, {
        issuer: this.#issuer,
        audience: this.#audience,
        algorithms: ["RS256"],
        typ: "JWT",
        clockTolerance: 0,
        requiredClaims: ["iss", "aud", "sub", "azp", "iat", "exp", "jti"],
        currentDate: new Date(now * 1000),
      }));
    } catch (error) {
      const code = object(error) ? error.code : undefined;
      if (
        typeof code === "string" &&
        [
          "ERR_JWT_EXPIRED",
          "ERR_JWT_CLAIM_VALIDATION_FAILED",
          "ERR_JWS_SIGNATURE_VERIFICATION_FAILED",
          "ERR_JWS_INVALID",
          "ERR_JWT_INVALID",
          "ERR_JOSE_ALG_NOT_ALLOWED",
          "ERR_JOSE_NOT_SUPPORTED",
          "ERR_JWKS_NO_MATCHING_KEY",
        ].includes(code)
      )
        return null;
      throw new IdentityProviderUnavailable();
    }
    if (
      payload.typ !== "Bearer" ||
      !text(payload.sub) ||
      !text(payload.azp) ||
      !text(payload.jti) ||
      !this.#clients.has(payload.azp) ||
      !(Array.isArray(payload.aud) ? payload.aud : [payload.aud]).includes(
        this.#clientId,
      ) ||
      typeof payload.iat !== "number" ||
      typeof payload.exp !== "number" ||
      !Number.isSafeInteger(payload.iat) ||
      !Number.isSafeInteger(payload.exp) ||
      (payload.nbf !== undefined &&
        (typeof payload.nbf !== "number" ||
          !Number.isSafeInteger(payload.nbf) ||
          payload.nbf < 0)) ||
      payload.iat < 0 ||
      payload.iat > now ||
      payload.exp <= now ||
      payload.exp <= payload.iat ||
      payload.exp - payload.iat > this.#lifetime
    )
      return null;
    const binding = this.#bindings.get(payload.sub);
    if (!binding) return null;
    const form = new URLSearchParams({
      token,
      token_type_hint: "access_token",
      client_id: this.#clientId,
      client_secret: this.#secret,
    });
    const response = await boundedJsonResponse(
      this.#issuer + "/protocol/openid-connect/token/introspect",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Accept: "application/json",
        },
        body: form,
      },
      this.#timeout,
    );
    const introspection = await response.json();
    if (!object(introspection) || typeof introspection.active !== "boolean")
      throw new IdentityProviderUnavailable();
    if (!introspection.active) return null;
    if (
      introspection.sub !== payload.sub ||
      introspection.exp !== payload.exp ||
      introspection.client_id !== payload.azp
    )
      throw new IdentityProviderUnavailable();
    // Network checks may outlive the JWT's remaining lifetime.
    if (payload.exp <= Math.floor(Date.now() / 1000)) return null;
    const resources = object(payload.resource_access)
      ? payload.resource_access
      : {};
    const resource = resources[this.#audience];
    const roles =
      object(resource) && Array.isArray(resource.roles)
        ? resource.roles.filter((role) => text(role))
        : [];
    const principal = Object.freeze({
      subject: payload.sub,
      entity: binding.entity,
      kid: binding.kid,
      clientId: payload.azp,
      roles: Object.freeze([...new Set(roles)]),
      expiresAt: payload.exp,
    });
    this.#tokens.set(principal, token);
    return principal;
  }
  /** Probe discovery/key availability and introspection credentials without a user's bearer.
   * Endpoints remain pinned; discovery never redirects authentication traffic.
   */
  async ready() {
    try {
      const discovery = await (
        await boundedJsonResponse(
          this.#issuer + "/.well-known/openid-configuration",
          { method: "GET", headers: { Accept: "application/json" } },
          this.#timeout,
        )
      ).json();
      if (
        !object(discovery) ||
        discovery.issuer !== this.#issuer ||
        discovery.jwks_uri !==
          this.#issuer + "/protocol/openid-connect/certs" ||
        discovery.introspection_endpoint !==
          this.#issuer + "/protocol/openid-connect/token/introspect"
      )
        return false;
      await this.#jwks.reload();
      if (
        !this.#jwks
          .jwks()
          ?.keys.some(
            (key) =>
              key.kty === "RSA" &&
              (key.alg === undefined || key.alg === "RS256") &&
              typeof key.n === "string" &&
              typeof key.e === "string",
          )
      )
        return false;
      const response = await boundedJsonResponse(
        this.#issuer + "/protocol/openid-connect/token/introspect",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            Accept: "application/json",
          },
          body: new URLSearchParams({
            client_id: this.#clientId,
            client_secret: this.#secret,
            token: "xeip-readiness-invalid-token",
          }),
        },
        this.#timeout,
      );
      const probe = await response.json();
      return object(probe) && probe.active === false;
    } catch {
      return false;
    }
  }
  /** Forget a completed request or disconnected session's bearer immediately.
   * @param {OrganizationPrincipal} principal
   */
  release(principal) {
    this.#tokens.delete(principal);
  }
  /** @param {OrganizationPrincipal} principal @returns {Promise<boolean>} */
  async revalidate(principal) {
    const token = this.#tokens.get(principal);
    if (!token || principal.expiresAt <= Math.floor(Date.now() / 1000)) {
      this.release(principal);
      return false;
    }
    try {
      const renewed = await this.authenticate("Bearer " + token);
      if (!renewed) {
        this.release(principal);
        return false;
      }
      this.release(renewed);
      // A connection may close while its provider requests are in flight.
      return this.#tokens.get(principal) === token;
    } catch (error) {
      this.release(principal);
      throw error;
    }
  }
}
