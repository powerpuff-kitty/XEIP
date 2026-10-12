import { ApprovalClient, readResponse } from "./client.mjs";
import { loadDevice, createDevice } from "./device.mjs";
import { browserSession } from "./session.mjs";
/** @typedef {import('../contracts.js').ActionInspection} Review */
/** @typedef {{subject:string,entity:string,kid:string,expiresAt:number}} Profile */
/** @template {HTMLElement} T @param {string} id @returns {T} */
const element = (id) => /** @type {T} */ (document.getElementById(id));
const notice = element("notice");
/** @type {import('./session.mjs').Bootstrap} */ let configuration;
/** @type {ReturnType<typeof browserSession>|undefined} */ let session;
/** @type {import('./device.mjs').Device|null} */ let device = null;
/** @type {Profile|null} */ let profile = null;
/** @type {ApprovalClient|undefined} */ let client;
/** @type {Review|null} */ let review = null;
let subject = "",
  busy = false,
  epoch = 0;
/** @type {AbortController|undefined} */ let active;
/** @param {string} message @param {boolean} [error] */
function announce(message, error = false) {
  notice.textContent = message;
  notice.dataset.error = String(error);
}
function controls() {
  /** @type {HTMLFieldSetElement} */ (element("lookup-fields")).disabled =
    busy || !client;
  for (const id of ["create-device", "check-enrollment", "sign-in"])
    /** @type {HTMLButtonElement} */ (element(id)).disabled = busy;
  const a = review?.proposal.action;
  const live = !!a && a.expiresAt > Math.floor(Date.now() / 1000);
  const eligible = !busy && !!client && live;
  const distinct =
    !!a &&
    a.actor.subject !== profile?.subject &&
    a.actor.entity !== profile?.entity;
  for (const id of ["approve", "reject"])
    /** @type {HTMLButtonElement} */ (element(id)).disabled = !(
      eligible &&
      distinct &&
      review?.state === "pending"
    );
  /** @type {HTMLButtonElement} */ (element("revoke")).disabled = !(
    eligible && ["pending", "approved"].includes(review?.state ?? "")
  );
  if (a && !live)
    element("decision-help").textContent =
      "This action has expired. Its history remains available, but it cannot be approved or executed.";
}
function clearReview() {
  review = null;
  element("review").hidden = true;
  element("empty-state").hidden = false;
  element("action-details").replaceChildren();
  element("proof-details").replaceChildren();
  element("arguments").textContent = "";
  element("result").textContent = "";
  controls();
}
function invalidated() {
  epoch++;
  active?.abort();
  client?.close();
  client = undefined;
  profile = null;
  subject = "";
  device = null;
  clearReview();
  element("account").textContent = "Session ended";
  element("sign-out").hidden = true;
  element("sign-in").hidden = true;
  element("create-device").hidden = true;
  element("check-enrollment").hidden = true;
  element("enrollment").hidden = true;
  element("enrollment-label").hidden = true;
  element("device-status").textContent = "Reload this page to sign in again.";
  announce(
    "Your session ended. Reload to sign in. Existing approvals remain in effect.",
    true,
  );
}
/** @param {unknown} error */
function message(error) {
  const code =
    error && typeof error === "object" && "code" in error ? error.code : "";
  const messages = /** @type {Record<string,string>} */ ({
    forbidden:
      "This account or device is not permitted. Ask your operator to check enrollment and membership.",
    unauthenticated: "Sign in again to continue.",
    session_changed: "Your account changed. Reload and sign in again.",
    conflict: "The action changed or is no longer eligible. Inspect it again.",
    not_actionable:
      "This action is expired, already decided, or cannot be approved by its requester.",
    review_required: "Inspect the action again before making a decision.",
    invalid_response:
      "The response could not be verified. Inspect again before deciding.",
    device_corrupt:
      "This browser key is damaged. Ask your operator to revoke it and arrange re-enrollment; it has not been replaced.",
    storage_unavailable:
      "Browser key storage is unavailable. Enable site storage and try again.",
    crypto_unavailable:
      "This browser does not support the required signing keys. Use a supported current browser.",
    busy: "Another request is still running. Wait, then inspect again.",
  });
  return (
    (typeof code === "string" && messages[code]) ||
    "The operation could not be confirmed. Inspect the action again; do not assume a decision failed."
  );
}
/** @param {(current:()=>void,signal:AbortSignal)=>Promise<void>} operation */
async function run(operation) {
  if (busy) return;
  busy = true;
  controls();
  const stamp = epoch;
  const abort = new AbortController();
  active = abort;
  const current = () => {
    if (epoch !== stamp || abort.signal.aborted) throw Error("cancelled");
  };
  const timeout = setTimeout(() => {
    abort.abort();
    session?.close();
  }, 25000);
  const interrupted = new Promise((_, reject) =>
    abort.signal.addEventListener("abort", () => reject(Error("cancelled")), {
      once: true,
    }),
  );
  try {
    await Promise.race([operation(current, abort.signal), interrupted]);
  } catch (error) {
    if (epoch === stamp) {
      clearReview();
      announce(message(error), true);
    }
  } finally {
    clearTimeout(timeout);
    abort.abort();
    if (active === abort) active = undefined;
    busy = false;
    controls();
  }
}
/** @param {string} path @param {AbortSignal} signal @param {string} [token] */
async function json(path, signal, token) {
  const response = await fetch(path, {
    signal,
    cache: "no-store",
    credentials: "omit",
    redirect: "error",
    headers: token ? { Authorization: "Bearer " + token } : {},
  });
  if (response.status !== 200) {
    await response.body?.cancel();
    throw Object.assign(Error(), {
      code:
        response.status === 401
          ? "unauthenticated"
          : response.status === 403
            ? "forbidden"
            : "unavailable",
    });
  }
  return readResponse(response, signal);
}
/** @param {()=>void} current @param {AbortSignal} signal */
async function connect(current, signal) {
  client?.close();
  client = undefined;
  profile = null;
  clearReview();
  if (!device || !session) return;
  const token = await session.token();
  current();
  const value = await json("/v1/console/profile", signal, token.token);
  current();
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(",") !== "entity,expiresAt,kid,subject"
  )
    throw Error();
  const candidate = /** @type {Profile} */ (/** @type {unknown} */ (value));
  if (
    candidate.subject !== subject ||
    candidate.kid !== device.kid ||
    !Number.isSafeInteger(candidate.expiresAt) ||
    candidate.expiresAt <= Math.floor(Date.now() / 1000)
  ) {
    element("device-status").textContent =
      "This key is not enrolled for the signed-in account. Send the public request to your operator.";
    announce(
      "Device enrollment does not match. No action can be approved.",
      true,
    );
    return;
  }
  client = new ApprovalClient({
    origin: location.origin,
    gateway: configuration.gateway,
    principal: candidate,
    privateKey: device.privateKey,
    token: () => /** @type {NonNullable<typeof session>} */ (session).token(),
  });
  profile = candidate;
  element("device-status").textContent =
    "Enrolled key matches this account. Signed actions still require live server checks.";
  announce("Ready. Enter the session and action IDs to inspect a request.");
}
/** @param {()=>void} current @param {AbortSignal} signal */
async function showDevice(current, signal) {
  if (!device) {
    element("create-device").hidden = false;
    element("device-status").textContent =
      "No key is stored for this account in this browser. Create one to request enrollment.";
    announce(
      "Create a browser key, then ask your operator to enroll its public key.",
    );
    return;
  }
  element("create-device").hidden = true;
  element("check-enrollment").hidden = false;
  element("enrollment").hidden = false;
  element("enrollment-label").hidden = false;
  /** @type {HTMLTextAreaElement} */ (element("enrollment")).value =
    JSON.stringify(
      { issuer: configuration.issuer, subject, kid: device.kid },
      null,
      2,
    );
  await connect(current, signal);
}
/** @param {string} destination @param {[string,string,boolean?][]} rows */
function details(destination, rows) {
  const list = element(destination);
  list.replaceChildren();
  for (const [label, value, code] of rows) {
    const term = document.createElement("dt"),
      description = document.createElement("dd");
    term.textContent = label;
    description.textContent = value;
    if (code) description.className = "code";
    list.append(term, description);
  }
}
/** @param {Review} value */
function render(value) {
  review = value;
  const a = value.proposal.action;
  element("review").hidden = false;
  element("empty-state").hidden = true;
  element("action-state").textContent = value.state;
  element("action-heading").textContent = a.tool;
  details("action-details", [
    ["Action", a.id],
    ["Session", a.session],
    ["Requester", a.actor.subject],
    ["Entity", a.actor.entity, true],
    ["Device key", a.actor.kid, true],
    ["Target", a.target.id],
    ["Revision", a.target.revision],
    ["Recipient", a.target.recipient, true],
    ["Expires", new Date(a.expiresAt * 1000).toISOString()],
  ]);
  details("proof-details", [
    ["Policy", a.policy, true],
    ["Digest", value.proposal.digest, true],
  ]);
  element("arguments").textContent = JSON.stringify(a.arguments, null, 2);
  element("result-section").hidden = value.result === null;
  element("result").textContent = JSON.stringify(value.result, null, 2);
  element("decision-help").textContent =
    value.state === "pending"
      ? "Read the full request above before deciding."
      : value.state === "approved"
        ? "Consent is recorded. Execution may not have started; inspect again for its current state."
        : value.state === "indeterminate"
          ? "The tool outcome is uncertain. Ask an operator to reconcile it; do not submit a replacement action blindly."
          : "This is a recorded action state. Inspect again to check for updates.";
  controls();
  element("action-heading").focus();
}
element("sign-in").addEventListener(
  "click",
  () =>
    void run(async () => {
      await session?.login();
    }),
);
element("sign-out").addEventListener("click", () => session?.logout());
element("create-device").addEventListener(
  "click",
  () =>
    void run(async (current, signal) => {
      const created = await createDevice(configuration.issuer, subject);
      current();
      device = created;
      await showDevice(current, signal);
    }),
);
element("check-enrollment").addEventListener("click", () => void run(connect));
element("inspect-form").addEventListener("submit", (event) => {
  event.preventDefault();
  void run(async (current) => {
    const activeClient = client;
    if (!activeClient) return;
    clearReview();
    announce("Checking the signed request…");
    const value = await activeClient.inspect(
      /** @type {HTMLInputElement} */ (element("session-id")).value,
      /** @type {HTMLInputElement} */ (element("action-id")).value,
    );
    current();
    render(value);
    announce("Request verified. Review its details before deciding.");
  });
});
for (const operation of /** @type {const} */ (["approve", "reject", "revoke"]))
  element(operation).addEventListener(
    "click",
    () =>
      void run(async (current) => {
        const displayed = review,
          activeClient = client;
        if (!displayed || !activeClient) return;
        clearReview();
        announce("Recording your decision…");
        const value = await (operation === "revoke"
          ? activeClient.revoke(displayed)
          : activeClient.decide(displayed, operation));
        current();
        render(value);
        announce(
          operation === "approve"
            ? "Approval recorded for this exact request. This is not confirmation of execution."
            : operation === "reject"
              ? "Rejection recorded."
              : "Consent revoked.",
        );
      }),
  );
setInterval(controls, 1000);
void run(async (current, signal) => {
  if (location.protocol !== "https:") throw Error();
  const value = await json("/console/config", signal);
  current();
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(",") !==
      "audience,clientId,gateway,issuer" ||
    !Object.values(value).every((v) => typeof v === "string")
  )
    throw Error();
  configuration = /** @type {import('./session.mjs').Bootstrap} */ (
    /** @type {unknown} */ (value)
  );
  session = browserSession(configuration, invalidated);
  const account = await session.init();
  current();
  if (!account) {
    element("sign-in").hidden = false;
    announce("Sign in to review actions with your enrolled browser key.");
    return;
  }
  subject = account;
  element("account").textContent = account;
  element("sign-in").hidden = true;
  element("sign-out").hidden = false;
  device = await loadDevice(configuration.issuer, account);
  current();
  await showDevice(current, signal);
});
