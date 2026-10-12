import type { Json } from "./types.js";

export type ActionRequest = {
  id: string;
  session: string;
  target: string;
  tool: string;
  arguments: { [key: string]: Json };
  expiresAt: number;
};
export type Action = {
  v: string;
  id: string;
  session: string;
  actor: { subject: string; entity: string; kid: string };
  target: { id: string; revision: string; recipient: string };
  tool: string;
  arguments: { [key: string]: Json };
  expiresAt: number;
  policy: string;
};
export type Proposal = { action: Action; digest: string };

export type OrganizationPrincipal = Readonly<{
  subject: string;
  entity: string;
  kid: string;
  clientId: string;
  roles: readonly string[];
  expiresAt: number;
}>;

/** Implementations retain bearer authority privately, only for this request. */
export type Authentication = {
  authenticate(header: unknown): Promise<OrganizationPrincipal | null>;
  revalidate(principal: OrganizationPrincipal): Promise<boolean>;
  release(principal: OrganizationPrincipal): void;
};

export type AuthorizationContext = {
  phase: string;
  proposal: Proposal;
  approver?: OrganizationPrincipal;
};
export type Authorizer = (
  principal: OrganizationPrincipal,
  context: AuthorizationContext,
) => Promise<boolean>;

export type ActionOutcome = "succeeded" | "failed" | "indeterminate";
export type ActionState =
  | "pending"
  | "approved"
  | "rejected"
  | "revoked"
  | "executing"
  | ActionOutcome;

/** Authorized status inspection never includes an execution capability. */
export type ActionInspection = {
  proposal: Proposal;
  state: ActionState;
  result: Json;
};
/** Internal adapter response; the controller removes claimId before exposure. */
export type ActionRecord = ActionInspection & { claimId: string | null };
export type ExecutionClaim = ActionRecord & {
  approver: OrganizationPrincipal;
};

/**
 * Mutations and their audit events commit atomically after late live checks.
 * A failed/ambiguous claim never authorizes an effect. Only a newly committed
 * claim is usable; previously consumed claims cannot be recovered for replay.
 */
export type ActionLedger = {
  inspect(
    principal: OrganizationPrincipal,
    session: string,
    id: string,
  ): Promise<ActionInspection>;
  propose(
    principal: OrganizationPrincipal,
    request: ActionRequest,
  ): Promise<ActionRecord>;
  decide(
    principal: OrganizationPrincipal,
    session: string,
    id: string,
    digest: string,
    decision: "approve" | "reject",
  ): Promise<ActionRecord>;
  revoke(
    principal: OrganizationPrincipal,
    session: string,
    id: string,
    digest: string,
  ): Promise<ActionRecord>;
  claim(
    principal: OrganizationPrincipal,
    session: string,
    id: string,
    digest: string,
  ): Promise<ExecutionClaim>;
  /** Internal capability only; records outcomes after caller expiry/disconnect. */
  finish(
    session: string,
    id: string,
    claimId: string,
    outcome: ActionOutcome,
    result?: Json,
  ): Promise<ActionRecord>;
};

/** Invoke the live guard just before sending; never retry an uncertain effect. */
export type EffectConnector = {
  call(
    action: Action,
    options: {
      signal?: AbortSignal;
      beforeSend: () => Promise<boolean>;
      dispatch?: ToolDispatch;
    },
  ): Promise<Json>;
};

/** Request-scoped control revision. Lock before action rows; keep through commit. */
export type ActionControlFence = {
  lock(client: import("pg").PoolClient): Promise<void>;
  current(): boolean;
};

/** Calls the provided fetch synchronously after final checks; never defers invocation. */
export type ToolDispatch = (send: () => Promise<Response>) => Promise<Response>;
export type ControlDispatchFence = ActionControlFence & {
  validate(): Promise<void>;
  dispatch<T>(send: () => T): T;
};
