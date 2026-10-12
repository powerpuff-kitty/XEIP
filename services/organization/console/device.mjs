/** Browser-owned device signing keys. Creation never implies enrollment. */
import { encodeKeyId } from "../../../sdks/typescript/dist/identity.js";
/** @typedef {{kid:string, publicKey:CryptoKey, privateKey:CryptoKey}} Device */
export class DeviceError extends Error {
  /** @param {string} code */
  constructor(code) {
    super(code);
    this.name = "DeviceError";
    this.code = code;
  }
}
/** @param {string} issuer @param {string} subject */
function namespace(issuer, subject) {
  try {
    const url = new URL(issuer);
    if (
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      typeof subject !== "string" ||
      !subject ||
      subject.length > 256 ||
      /[\u0000-\u001f\u007f]/.test(subject)
    )
      throw Error();
    return JSON.stringify([issuer, subject]);
  } catch {
    throw new DeviceError("invalid_identity");
  }
}
/** @returns {Promise<IDBDatabase>} */
function open() {
  return new Promise((resolve, reject) => {
    let done = false;
    const timer = setTimeout(() => fail(), 10000);
    const fail = () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      reject(new DeviceError("storage_unavailable"));
    };
    let request;
    try {
      request = indexedDB.open("xeip-approval-devices", 1);
    } catch {
      fail();
      return;
    }
    request.onupgradeneeded = () => {
      request.result.createObjectStore("devices");
    };
    request.onblocked = fail;
    request.onerror = fail;
    request.onsuccess = () => {
      if (done) {
        request.result.close();
        return;
      }
      done = true;
      clearTimeout(timer);
      request.result.onversionchange = () => request.result.close();
      resolve(request.result);
    };
  });
}
/** Read or atomically insert an absent key. Never overwrite an existing record.
 * @param {string} key @param {Device} [candidate] @returns {Promise<unknown>}
 */
async function stored(key, candidate) {
  const db = await open();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(
        "devices",
        candidate ? "readwrite" : "readonly",
      );
      const timer = setTimeout(() => {
        try {
          tx.abort();
        } catch {}
      }, 10000);
      const request = tx.objectStore("devices").get(key);
      /** @type {unknown} */
      let result;
      request.onsuccess = () => {
        result = request.result;
        if (result === undefined && candidate) {
          tx.objectStore("devices").add(candidate, key);
          result = candidate;
        }
      };
      tx.oncomplete = () => {
        clearTimeout(timer);
        resolve(result);
      };
      tx.onabort = () => {
        clearTimeout(timer);
        reject(new DeviceError("storage_unavailable"));
      };
      tx.onerror = () => {};
    });
  } catch {
    throw new DeviceError("storage_unavailable");
  } finally {
    db.close();
  }
}
/** Confirm persisted keys, not just their labels. @param {unknown} value @returns {Promise<Device>} */
async function checked(value) {
  try {
    const device = /** @type {Device} */ (value);
    if (
      !device ||
      Object.keys(device).sort().join(",") !== "kid,privateKey,publicKey" ||
      !(device.privateKey instanceof CryptoKey) ||
      !(device.publicKey instanceof CryptoKey) ||
      device.privateKey.type !== "private" ||
      device.privateKey.extractable ||
      device.privateKey.algorithm.name !== "Ed25519" ||
      device.privateKey.usages.join(",") !== "sign" ||
      device.publicKey.type !== "public" ||
      !device.publicKey.extractable ||
      device.publicKey.algorithm.name !== "Ed25519" ||
      device.publicKey.usages.join(",") !== "verify"
    )
      throw Error();
    const kid = encodeKeyId(
      new Uint8Array(await crypto.subtle.exportKey("raw", device.publicKey)),
    );
    if (kid !== device.kid) throw Error();
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const signature = await crypto.subtle.sign(
      "Ed25519",
      device.privateKey,
      challenge,
    );
    if (
      !(await crypto.subtle.verify(
        "Ed25519",
        device.publicKey,
        signature,
        challenge,
      ))
    )
      throw Error();
    return Object.freeze({
      kid,
      publicKey: device.publicKey,
      privateKey: device.privateKey,
    });
  } catch {
    throw new DeviceError("device_corrupt");
  }
}
/** @param {string} issuer @param {string} subject @returns {Promise<Device|null>} */
export async function loadDevice(issuer, subject) {
  const value = await stored(namespace(issuer, subject));
  return value === undefined ? null : checked(value);
}
/** Explicit user action only. Returns the winner if another tab creates first.
 * @param {string} issuer @param {string} subject @returns {Promise<Device>}
 */
export async function createDevice(issuer, subject) {
  const key = namespace(issuer, subject);
  const existing = await stored(key);
  if (existing !== undefined) return checked(existing);
  let pair;
  try {
    pair = /** @type {CryptoKeyPair} */ (
      await crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"])
    );
  } catch {
    throw new DeviceError("crypto_unavailable");
  }
  const kid = encodeKeyId(
    new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)),
  );
  return checked(
    await stored(key, {
      kid,
      publicKey: pair.publicKey,
      privateKey: pair.privateKey,
    }),
  );
}
