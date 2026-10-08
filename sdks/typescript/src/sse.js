/** Incremental SSE framing; keeps CRLF state across reads and bounds each unfinished frame. */
export class SseParser {
  constructor() {
    this.line = "";
    /** @type {string[]} */
    this.data = [];
    this.event = "";
    this.size = 0;
    this.afterCr = false;
    this.start = true;
  }
  /** @param {string} text @returns {{event: string, data: string}[]} */
  push(text) {
    const frames = [];
    for (const character of text) {
      if (this.start) { this.start = false; if (character === "\uFEFF") continue; }
      if (this.afterCr) {
        this.afterCr = false;
        if (character === "\n") continue;
      }
      this.size += character.length;
      if (this.size > 128 * 1024) throw new RangeError("SSE frame limit exceeded");
      if (character === "\r" || character === "\n") {
        this.afterCr = character === "\r";
        if (this.line === "") {
          if (this.data.length) frames.push({ event: this.event || "message", data: this.data.join("\n") });
          this.event = ""; this.data = []; this.size = 0;
        } else if (!this.line.startsWith(":")) {
          const colon = this.line.indexOf(":");
          const field = colon < 0 ? this.line : this.line.slice(0, colon);
          let value = colon < 0 ? "" : this.line.slice(colon + 1);
          if (value.startsWith(" ")) value = value.slice(1);
          if (field === "event") this.event = value;
          if (field === "data") this.data.push(value);
        }
        this.line = "";
      } else {
        this.line += character;
      }
    }
    return frames;
  }
}
