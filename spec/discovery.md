# XEIP discovery — draft 0.1

A service MAY expose an entity manifest at `/.well-known/xeip.json`. This is an XEIP-specific experimental convention, **not a registered well-known URI**, and producers SHOULD also support an RFC 8631 `Link: <...>; rel="service-desc"` header where suitable.

Manifests use [entity.schema.json](../schemas/entity.schema.json), which describes entity IDs, kinds, endpoints and capabilities. Clients MUST NOT treat a manifest as evidence of identity or authority by itself.

Supported patterns to investigate:
- Explicit URLs configured by a user or application.
- LAN advertisement (mDNS / DNS-SD) for local devices.
- Existing A2A Agent Cards and MCP endpoints referenced from capability descriptors.
- Organization-controlled or federated directories with signed/verifiable records.

Discovery is not a directory service requirement. Authentication, signature verification, endpoint trust, transport negotiation and privacy-preserving listings belong in a future normative security profile.
