import Keycloak from "keycloak-js";
/** @typedef {{issuer:string,clientId:string,gateway:string,audience:string}} Bootstrap */
export class SessionError extends Error {
  /** @param {string} code */
  constructor(code) {
    super(code);
    this.name = "SessionError";
    this.code = code;
  }
}
/** Keycloak endpoints are derived only from protected server configuration.
 * No URL, fragment, discovery document or user input selects a token destination.
 * @param {Bootstrap} configuration @param {()=>void} invalidated
 */
export function browserSession(configuration, invalidated) {
  const issuer = new URL(configuration.issuer);
  if (
    issuer.protocol !== "https:" ||
    issuer.username ||
    issuer.password ||
    issuer.search ||
    issuer.hash ||
    configuration.issuer.endsWith("/") ||
    !configuration.clientId ||
    !configuration.audience
  )
    throw new SessionError("invalid_configuration");
  const endpoint = configuration.issuer + "/protocol/openid-connect";
  const adapter = new Keycloak({
    clientId: configuration.clientId,
    oidcProvider: {
      authorization_endpoint: endpoint + "/auth",
      token_endpoint: endpoint + "/token",
      end_session_endpoint: endpoint + "/logout",
      userinfo_endpoint: endpoint + "/userinfo",
    },
  });
  const redirectUri = location.origin + "/console/";
  let closed = false;
  /** @type {string|undefined} */ let subject;
  const invalidate = () => {
    if (closed) {
      // An in-flight code exchange or refresh can install tokens after closure.
      adapter.clearToken();
      return;
    }
    closed = true;
    adapter.clearToken();
    invalidated();
  };
  adapter.onAuthLogout = invalidate;
  adapter.onAuthRefreshError = invalidate;
  function credential() {
    const parsed = adapter.tokenParsed;
    const audience = Array.isArray(parsed?.aud) ? parsed.aud : [parsed?.aud];
    if (
      closed ||
      !adapter.authenticated ||
      !adapter.token ||
      !parsed ||
      parsed.iss !== configuration.issuer ||
      parsed.azp !== configuration.clientId ||
      !audience.includes(configuration.audience) ||
      typeof parsed.sub !== "string" ||
      !parsed.sub ||
      parsed.sub.length > 256 ||
      /[\u0000-\u001f\u007f]/.test(parsed.sub) ||
      !Number.isSafeInteger(parsed.exp) ||
      /** @type {number} */ (parsed.exp) <= Math.floor(Date.now() / 1000) ||
      (subject !== undefined && subject !== parsed.sub)
    ) {
      invalidate();
      throw new SessionError("session_changed");
    }
    subject = parsed.sub;
    return {
      subject,
      token: adapter.token,
      expiresAt: /** @type {number} */ (parsed.exp),
    };
  }
  return {
    async init() {
      try {
        const authenticated = await adapter.init({
          adapter: "default",
          flow: "standard",
          responseMode: "fragment",
          pkceMethod: "S256",
          useNonce: true,
          checkLoginIframe: false,
          redirectUri,
        });
        if (closed) throw new SessionError("unauthenticated");
        return authenticated ? credential().subject : null;
      } catch {
        invalidate();
        throw new SessionError("unauthenticated");
      }
    },
    async token() {
      if (closed) throw new SessionError("unauthenticated");
      try {
        await adapter.updateToken(30);
        return credential();
      } catch {
        invalidate();
        throw new SessionError("unauthenticated");
      }
    },
    async login() {
      if (closed) throw new SessionError("unauthenticated");
      await adapter.login({ redirectUri });
    },
    logout() {
      const destination = adapter.createLogoutUrl({ redirectUri });
      invalidate();
      location.assign(destination);
    },
    close: invalidate,
  };
}
