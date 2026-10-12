/** Shared adapter outcomes. Import these classes without loading an adapter. */
export class StoreConflict extends Error {
  constructor() {
    super("action state conflict");
    this.name = "StoreConflict";
  }
}

export class StoreUnavailable extends Error {
  constructor() {
    super("action store unavailable");
    this.name = "StoreUnavailable";
  }
}

export class ConnectorFailure extends Error {
  /** @param {boolean} sent */
  constructor(sent) {
    super("MCP target unavailable");
    this.name = "ConnectorFailure";
    this.sent = sent;
  }
}
