export type Json = null | boolean | number | string | JsonArray | JsonObject;
export interface JsonArray extends ReadonlyArray<Json> {}
export interface JsonObject {
  [key: string]: Json;
}
