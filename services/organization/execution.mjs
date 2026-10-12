/** Durable claim -> one effect -> durable outcome. No automatic replay or recovery execution. */
import { ConnectorFailure } from "./errors.mjs";
/** @typedef {import('./contracts.js').OrganizationPrincipal} Principal */
/** @param {import('./actions.mjs').ActionPolicy} policy @param {import('./contracts.js').EffectConnector} connector @param {()=>import('./contracts.js').ControlDispatchFence} [captureControl] */
export function createActionExecutor(policy, connector, captureControl) {
  /** @param {Principal} principal @param {{session:string,id:string,digest?:string}} command
   * @param {{store:Pick<import('./contracts.js').ActionLedger,'claim'|'finish'>,authorize:import('./contracts.js').Authorizer,signal?:AbortSignal,current?:()=>boolean}} context
   */
  return async (principal, command, { store, authorize, signal, current }) => {
    const control = captureControl?.();
    // An unavailable/ambiguous claim must escape here, before any connector work.
    const claim = await store.claim(
      principal,
      command.session,
      command.id,
      /** @type {string} */ (command.digest),
    );
    const eligible = () =>
      !signal?.aborted &&
      (!current || current()) &&
      !!claim.approver &&
      policy.canExecute(principal, claim.proposal) &&
      policy.canApprove(claim.approver, claim.proposal);
    /** @type {'succeeded'|'failed'|'indeterminate'} */ let outcome =
      "indeterminate";
    /** @type {import('./types.js').Json} */ let result = null;
    try {
      result = await connector.call(claim.proposal.action, {
        signal,
        beforeSend: async () =>
          eligible() &&
          (control ? (await control.validate(), true) : true) &&
          (await authorize(principal, {
            phase: "effect",
            proposal: claim.proposal,
            ...(claim.approver ? { approver: claim.approver } : {}),
          })) &&
          eligible(),
        dispatch: (send) => {
          if (!eligible()) throw new ConnectorFailure(false);
          return control ? control.dispatch(send) : send();
        },
      });
      outcome =
        result !== null &&
        typeof result === "object" &&
        !Array.isArray(result) &&
        "isError" in result &&
        result.isError === true
          ? "failed"
          : "succeeded";
    } catch (error) {
      outcome =
        error instanceof ConnectorFailure && !error.sent
          ? "failed"
          : "indeterminate";
    }
    // Failure here remains unavailable. Never return an unrecorded success or repeat an effect.
    return store.finish(
      command.session,
      command.id,
      /** @type {string} */ (claim.claimId),
      outcome,
      result,
    );
  };
}
