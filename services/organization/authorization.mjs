/** Compose provider authentication and live entity trust at the store's use-time boundary.
 * This does not verify request signatures; the transport must do so before store calls.
 * @param {Pick<import('./contracts.js').Authentication,'revalidate'>} authentication
 * @param {{allows: (principal: {entity: string, kid: string}) => boolean}} trust
 * @returns {import('./contracts.js').Authorizer}
 */
export function liveActionAuthorizer(authentication, trust) {
  return async (principal, context) => {
    if (!(await authentication.revalidate(principal))) return false;
    return (
      trust.allows(principal) &&
      (!context.approver || trust.allows(context.approver))
    );
  };
}
