/** Public boundary for the runtime-verified shared entity trust implementation. */
export class EntityTrustPolicy {
  constructor(
    configuration: {
      trustDir: string;
      maxAgeSeconds: number;
      knownExtensions?: string[];
    },
    keyDocuments: unknown[],
    statusDocuments: unknown[],
  );
  update(provisioning: unknown): void;
  updateAsync(
    provisioning: unknown,
    options?: { signal?: AbortSignal },
  ): Promise<void>;
  allows(principal: { entity: string; kid: string }): boolean;
  status(): {
    state: "ready" | "empty" | "stale" | "failed" | "closed";
    entities: number;
  };
  readonly entityCount: number;
  verify(envelope: unknown): { valid: boolean; reason?: string };
  close(): void;
}
