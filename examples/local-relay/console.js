import { SseParser } from "/sse.js";
import { validateEnvelope } from "/validation.js";

const $ = id => document.getElementById(id);
const names = {
  "urn:xeip:entity:human-01": "Human 01",
  "urn:xeip:entity:agent-01": "Agent 01",
  "urn:xeip:entity:camera-01": "Camera 01"
};
let controller = null;
let active = false;
let streamCount = 0;
let streamWorker = null;

function status(message, live = false) {
  $("status").textContent = message;
  $("dot").classList.toggle("live", live);
  $("connect").disabled = live;
  $("disconnect").disabled = !live;
  active = live;
}
function logEnvelope(message, outbound = false) {
  $("empty").hidden = true;
  const item = document.createElement("article");
  item.className = "item" + (outbound ? " outbound" : "");
  const header = document.createElement("header");
  const from = document.createElement("span");
  from.className = "from";
  from.textContent = (names[message.sender] ?? message.sender) + " · " + message.kind;
  const time = document.createElement("span");
  time.className = "time";
  time.textContent = new Date(message.timestamp).toLocaleTimeString();
  header.append(from, time);
  const route = document.createElement("div");
  route.className = "route";
  route.textContent = "→ " + (names[message.recipient] ?? message.recipient ?? "Everyone");
  const content = document.createElement("p");
  content.textContent = typeof message.body.data === "string" ? message.body.data : JSON.stringify(message.body.data);
  item.append(header, route, content);
  $("messages").append(item);
  $("messages").scrollTop = $("messages").scrollHeight;
}
function consumeSse(frame) {
  if (frame.event !== "xeip.message") return;
  const msg = JSON.parse(frame.data);
  validateEnvelope(msg);
  logEnvelope(msg);
  streamCount += 1;
  $("received").textContent = String(streamCount);
}
async function connect() {
  const token = $("token").value;
  const session = $("session").value.trim();
  const entity = $("actor").value;
  if (token.length < 16 || !session.includes(":")) return status("Enter valid token and session URI");
  controller?.abort();
  const candidate = new AbortController();
  controller = candidate;
  try {
    const url = new URL("/events", location.href);
    url.searchParams.set("session", session);
    url.searchParams.set("entity", entity);
    const response = await fetch(url, { headers: { Authorization: "Bearer " + token }, signal: candidate.signal });
    if (!response.ok || !response.body) throw Error("HTTP " + response.status);
    status("Connected as " + (names[entity] ?? entity), true);
    streamWorker = (async () => {
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      const parser = new SseParser();
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          for (const frame of parser.push(decoder.decode(value, { stream: true }))) consumeSse(frame);
        }
      } catch (err) {
        if (!candidate.signal.aborted) status("Stream interrupted: " + err.message);
      } finally {
        await reader.cancel().catch(() => {});
        if (controller === candidate && !candidate.signal.aborted) status("Disconnected");
      }
    })();
  } catch (err) {
    if (!candidate.signal.aborted) status("Connection failed: " + err.message);
  }
}
function disconnect() {
  controller?.abort();
  controller = null;
  status("Disconnected");
}
async function send(event) {
  event.preventDefault();
  if (!active) return status("Connect before sending");
  const body = $("body").value.trim();
  if (!body) return;
  const message = {
    xeip: "0.1",
    id: "urn:uuid:" + crypto.randomUUID(),
    kind: $("kind").value,
    sender: $("actor").value,
    session: $("session").value.trim(),
    timestamp: new Date().toISOString(),
    body: { contentType: "text/plain", data: body }
  };
  if ($("recipient").value) message.recipient = $("recipient").value;
  $("envelope").textContent = JSON.stringify(message, null, 2);
  const button = $("send");
  button.disabled = true;
  try {
    const response = await fetch("/messages", {
      method: "POST",
      headers: { Authorization: "Bearer " + $("token").value, "Content-Type": "application/json" },
      body: JSON.stringify(message)
    });
    if (!response.ok) throw Error("HTTP " + response.status);
    const result = await response.json();
    $("delivered").textContent = String(result.delivered);
    $("body").value = "";
    if (message.recipient && message.recipient !== message.sender) logEnvelope(message, true);
  } catch (err) {
    status("Send failed: " + err.message, true);
  } finally {
    button.disabled = false;
  }
}
$("connect").addEventListener("click", connect);
$("disconnect").addEventListener("click", disconnect);
$("clear").addEventListener("click", () => {
  $("messages").replaceChildren($("empty"));
  $("empty").hidden = false;
  streamCount = 0;
  $("received").textContent = "0";
});
$("compose").addEventListener("submit", send);
$("body").addEventListener("keydown", event => {
  if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) $("compose").requestSubmit();
});
window.addEventListener("pagehide", disconnect);
