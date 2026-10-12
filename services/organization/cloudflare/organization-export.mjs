/** Ephemeral private export state. Never a durable receipt or execution authority. */
import { randomUUID } from "node:crypto";
import { canonicalize } from "../../../sdks/typescript/dist/identity.js";
import { snapshot } from "../actions.mjs";
import { StoreConflict, StoreUnavailable } from "../errors.mjs";
import { operatorIdentity } from "./profile.mjs";
import { encodeTrustCheckpoint } from "./trust-checkpoint.mjs";
import {
  validateOrganizationCheckpoint,
  organizationPageOptions,
} from "./organization-checkpoint.mjs";
import { components, limits, hash } from "./organization-bundle-record.mjs";
import { actionCursor, validateActionPage } from "./action-export.mjs";
import {
  authorityHistoryCursor,
  validateAuthorityHistoryPage,
} from "./authority-checkpoint.mjs";
import {
  adminHistoryCursor,
  validateAdminHistoryPage,
} from "./admin-checkpoint.mjs";

/** @typedef {typeof components[number]} Component */
/** @typedef {import('./organization-checkpoint.mjs').Checkpoint} Checkpoint */
/** @typedef {ReturnType<typeof organizationPageOptions>} Request */
/** @typedef {{readPage:(request:Request)=>Promise<unknown>|unknown,assertUsable:()=>void,close:()=>void}} Reader */
/** @typedef {Reader & {checkpoint:unknown}} Source */
/** @typedef {{bytes:number,sha256:string,parts:number}} Descriptor */
/** @typedef {{exportId:string,manifest:Checkpoint['manifest'],components:Record<Component,Descriptor>}} Description */
/** @typedef {{description:Description,buffers:Record<Component,Buffer>,authority:Checkpoint['authority'],administration:Checkpoint['administration'],reader:Reader}} Data */
/** @typedef {{operator:string,id:string,started:number,expires:number,last:number,timer?:ReturnType<typeof setTimeout>,stopped:Promise<never>,stop:()=>void,cleanup?:()=>void,data?:Data,busy:boolean}} Slot */
const PART_BYTES = 262144,
  IDLE_MS = 30000,
  LIFETIME_MS = 3600000;

export class OrganizationExports {
  #organization;
  #capture;
  #now;
  #closed = false;
  /** @type {Slot|undefined} */ #slot;
  /** @param {{organization:string,capture:()=>Promise<Source>,now?:()=>number}} options */
  constructor({ organization, capture, now = () => performance.now() }) {
    if (
      !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(organization) ||
      typeof capture !== "function" ||
      typeof now !== "function"
    )
      throw new TypeError("invalid organization export source");
    this.#organization = organization;
    this.#capture = capture;
    this.#now = now;
  }
  /** Release memory/readers before waking pending callers. @param {Slot} slot */
  #drop(slot) {
    if (this.#slot === slot) this.#slot = undefined;
    clearTimeout(slot.timer);
    slot.data = undefined;
    const cleanup = slot.cleanup;
    slot.cleanup = undefined;
    try {
      cleanup?.();
    } finally {
      slot.stop();
    }
  }
  /** @param {Slot} slot */
  #active(slot) {
    const now = this.#now();
    if (
      this.#closed ||
      this.#slot !== slot ||
      !Number.isFinite(now) ||
      now < slot.last ||
      now >= slot.expires
    ) {
      this.#drop(slot);
      throw new StoreUnavailable();
    }
    slot.last = now;
    return now;
  }
  /** @param {Slot} slot */
  #arm(slot) {
    clearTimeout(slot.timer);
    slot.timer = setTimeout(
      () => {
        try {
          this.#active(slot);
          this.#arm(slot);
        } catch {
          /* expiry disposes the slot */
        }
      },
      Math.max(1, slot.expires - this.#now()),
    );
    slot.timer.unref?.();
  }
  /** @param {Slot} slot */
  #renew(slot) {
    const now = this.#active(slot);
    slot.expires = Math.min(now + IDLE_MS, slot.started + LIFETIME_MS);
    this.#arm(slot);
  }
  /** @param {unknown} operator @param {unknown} id @returns {Slot & {data:Data}} */
  #get(operator, id) {
    const slot = this.#slot;
    if (!slot || operator !== slot.operator || id !== slot.id)
      throw new StoreUnavailable();
    this.#active(slot);
    if (!slot.data) throw new StoreUnavailable();
    try {
      slot.data.reader.assertUsable();
    } catch (error) {
      if (!(error instanceof StoreConflict)) this.#drop(slot);
      throw error instanceof StoreConflict ? error : new StoreUnavailable();
    }
    return /** @type {Slot & {data:Data}} */ (slot);
  }
  /** @param {unknown} operator @returns {Promise<Description>} */
  async begin(operator) {
    const identity = operatorIdentity({ operator });
    if (this.#closed) throw new StoreUnavailable();
    if (this.#slot) {
      try {
        this.#active(this.#slot);
      } catch {
        /* expired slot can be replaced */
      }
      if (this.#slot) throw new StoreConflict();
    }
    const started = this.#now();
    if (!Number.isFinite(started) || started < 0) throw new StoreUnavailable();
    let stop = () => {};
    const stopped = new Promise((_, reject) => {
      stop = () => reject(new StoreUnavailable());
    });
    stopped.catch(() => {});
    const slot = /** @type {Slot} */ ({
      operator: identity,
      id: randomUUID(),
      started,
      expires: started + IDLE_MS,
      last: started,
      stopped,
      stop,
      busy: false,
    });
    this.#slot = slot;
    this.#arm(slot);
    const capture = Promise.resolve()
      .then(() => {
        this.#active(slot);
        return this.#capture();
      })
      .then((source) => {
        if (this.#slot !== slot || this.#closed) {
          source.close();
          throw new StoreUnavailable();
        }
        slot.cleanup = source.close;
        this.#active(slot);
        source.assertUsable();
        const checkpoint = validateOrganizationCheckpoint(
          source.checkpoint,
          this.#organization,
        );
        const buffers = /** @type {Record<Component,Buffer>} */ ({}),
          descriptors = /** @type {Record<Component,Descriptor>} */ ({});
        for (const component of components) {
          const encoded =
            component === "trust"
              ? encodeTrustCheckpoint(checkpoint.trust, this.#organization)
              : canonicalize(checkpoint[component]);
          const bytes = Buffer.from(encoded + "\n");
          if (bytes.length > limits[component] + 1)
            throw new StoreUnavailable();
          buffers[component] = bytes;
          descriptors[component] = Object.freeze({
            bytes: bytes.length,
            sha256: hash(bytes),
            parts: Math.ceil(bytes.length / PART_BYTES),
          });
        }
        slot.data = {
          description: Object.freeze({
            exportId: slot.id,
            manifest: checkpoint.manifest,
            components: Object.freeze(descriptors),
          }),
          buffers,
          authority: checkpoint.authority,
          administration: checkpoint.administration,
          reader: {
            assertUsable: source.assertUsable,
            readPage: source.readPage,
            close: source.close,
          },
        };
        this.#renew(slot);
        return slot.data.description;
      });
    try {
      return await Promise.race([capture, slot.stopped]);
    } catch (error) {
      this.#drop(slot);
      throw error instanceof StoreConflict ? error : new StoreUnavailable();
    }
  }
  /** @param {unknown} operator @param {unknown} id @param {unknown} component @param {unknown} index */
  part(operator, id, component, index) {
    const slot = this.#get(operator, id);
    if (slot.busy) throw new StoreConflict();
    if (
      typeof component !== "string" ||
      !components.includes(/** @type {Component} */ (component)) ||
      !Number.isSafeInteger(index) ||
      Number(index) < 0
    )
      throw new TypeError("invalid organization export part");
    const name = /** @type {Component} */ (component),
      part = Number(index),
      bytes = slot.data.buffers[name];
    if (part >= slot.data.description.components[name].parts)
      throw new TypeError("invalid organization export part");
    const data = bytes
      .subarray(part * PART_BYTES, (part + 1) * PART_BYTES)
      .toString("base64");
    this.#renew(slot);
    return {
      exportId: slot.id,
      checkpointDigest: slot.data.description.manifest.digest,
      component: name,
      index: part,
      data,
    };
  }
  /** @param {unknown} operator @param {unknown} id @param {unknown} options */
  async page(operator, id, options) {
    const slot = this.#get(operator, id),
      request = organizationPageOptions(options),
      { data } = slot;
    let cursor;
    if (request.section === "actions") {
      actionCursor(request.cursor);
      if (request.cursor > data.description.manifest.actions.cut)
        throw new TypeError("invalid action cursor");
      cursor = request.cursor;
    } else if (request.section === "authority")
      cursor = authorityHistoryCursor(request.cursor, data.authority.revision);
    else
      cursor = adminHistoryCursor(
        request.cursor,
        data.administration.headSequence,
      );
    if (slot.busy) throw new StoreConflict();
    slot.busy = true;
    let received = false;
    try {
      const raw = await Promise.race([
        Promise.resolve().then(() => {
          this.#active(slot);
          return data.reader.readPage({ section: request.section, cursor });
        }),
        slot.stopped,
      ]);
      received = true;
      this.#get(operator, id);
      const value = snapshot(raw, 491520);
      if (
        !value ||
        typeof value !== "object" ||
        Array.isArray(value) ||
        Object.keys(value).sort().join(",") !== "checkpointDigest,page,section"
      )
        throw Error();
      const result =
        /** @type {{checkpointDigest:unknown,section:unknown,page:unknown}} */ (
          value
        );
      if (
        result.checkpointDigest !== data.description.manifest.digest ||
        result.section !== request.section
      )
        throw Error();
      if (request.section === "actions")
        validateActionPage(result.page, {
          cut: data.description.manifest.actions.cut,
          after: /** @type {number} */ (cursor),
        });
      else if (request.section === "authority")
        validateAuthorityHistoryPage(
          result.page,
          data.authority,
          /** @type {import('./authority-checkpoint.mjs').Cursor} */ (cursor),
        );
      else
        validateAdminHistoryPage(
          result.page,
          data.administration,
          /** @type {import('./admin-checkpoint.mjs').Cursor} */ (cursor),
        );
      if (Buffer.byteLength(canonicalize(result)) > 491520) throw Error();
      this.#renew(slot);
      return { exportId: slot.id, ...result };
    } catch (error) {
      if (
        error instanceof StoreConflict ||
        (!received && error instanceof TypeError)
      )
        throw error;
      this.#drop(slot);
      throw new StoreUnavailable();
    } finally {
      slot.busy = false;
    }
  }
  /** @param {unknown} operator @param {unknown} id */
  end(operator, id) {
    const slot = this.#slot;
    if (!slot || operator !== slot.operator || id !== slot.id)
      throw new StoreUnavailable();
    this.#active(slot);
    this.#drop(slot);
  }
  close() {
    this.#closed = true;
    if (this.#slot) this.#drop(this.#slot);
  }
}
