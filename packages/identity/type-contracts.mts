// Compile-only callers: preserve supported Node key forms and untrusted inputs.
// Included by the no-emit identity check; never part of the runtime module graph.
import type { JsonWebKeyInput, KeyObject, PrivateKeyInput } from "node:crypto";
import {
  signEnvelope,
  strictParse,
  verifySignedEnvelope,
} from "./signed-envelope.mjs";
import { decodeKeyId } from "./key-id.mjs";

declare const envelope: unknown;
declare const keyObject: KeyObject;
declare const seedOrDer: Uint8Array;
declare const pem: string;
declare const options: PrivateKeyInput;
declare const jwkOptions: JsonWebKeyInput;
declare const kid: string;

for (const privateKey of [keyObject, seedOrDer, pem, options, jwkOptions]) {
  signEnvelope(envelope, { privateKey, kid });
}

const parsed = strictParse(envelope);
verifySignedEnvelope(parsed);
decodeKeyId(envelope);
