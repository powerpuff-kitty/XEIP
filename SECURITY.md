# Security policy

**XEIP 0.1 is experimental and NOT safe for publicly exposed, untrusted or multi-tenant use.** The current demo relay uses one shared bearer token, no individual cryptographic identity verification, and no enforced group membership. It binds to loopback by default and must remain loopback-only.

## Reporting vulnerabilities

Please use GitHub's private **Report a vulnerability** feature (Security tab → Advisories) if enabled. If unavailable, open an issue that requests a private reporting channel **without disclosing exploit details or credentials**. Do not post sensitive evidence publicly.

## Supported versions

No stable releases are supported yet. Changes are made on main until a versioned release and maintenance policy are established.

See [spec/security.md](spec/security.md) for the future production threat model, required identity binding, authorization, signed/verifiable discovery, session admission, secure transport and command validation. A development token is **not** a replacement for these controls.
