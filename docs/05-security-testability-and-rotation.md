# Chapter 5: Security, testability, and rotation

Back to [docs index](index.md)

If this repo is meant to teach how to do mTLS properly, it has to cover more than just a working handshake.

## Security measures the repo should teach explicitly

### Certificate content

- Use SANs intentionally for service identity.
- Do not rely on Common Name alone for hostname validation.
- Keep EKU appropriate to the certificate role.
- Keep key usage appropriate to the certificate role.

### Key protection

- Prefer TPM-backed or otherwise non-exportable client keys when device identity matters.
- Prefer non-exportable server keys too when the host platform allows it.
- Restrict access to stores, files, containers, and secret backends.
- Clean up stale certificates and containers after renewal or device replacement.

### Trust management

- Distribute issuer bundles carefully.
- Separate server-validation trust from client-validation trust when appropriate.
- Plan explicitly for rollover and overlap periods.
- Decide whether to use revocation, short-lived certificates, or both.

### Observability

- Log certificate subjects, issuers, and thumbprints where appropriate.
- Monitor certificate expiry.
- Make trust-bundle changes visible and auditable.

## Testability guidance

One of the strongest patterns in this repo is that the file-based scenarios are easy to test end to end.

For example, `mtlsfiles` uses `runDemo(...)` and a `t.TempDir()`-backed setup in its integration test. That is the kind of structure that keeps TLS and mTLS code maintainable.

The repo should keep teaching these testing rules:

1. keep config parsing separate from runtime orchestration
2. keep certificate generation separate from certificate loading
3. keep server creation separate from demo orchestration
4. keep negative-path tests as first-class tests
5. use temp directories for file-backed scenarios
6. treat TPM or OS-store scenarios as Windows-specific integration paths

A useful long-term rule for this repo is:

- use `mtlsfiles` as the testability reference
- use `mtlstpm` as the secure-key-management reference

## Certificate rotation guidance

Certificate rotation should be part of the teaching story too.

### Leaf rotation

The repo should teach this rollout model:

1. issue a new certificate before the old one expires
2. import or publish it alongside the old one
3. keep runtime certificate selection stable
4. switch usage cleanly
5. remove the old certificate after successful rollout

### Intermediate-CA rotation

The repo should teach this model too:

1. distribute trust for the new intermediate
2. allow both old and new chains during migration
3. reissue leaves from the new intermediate
4. remove old trust only after all participants converge

This is the practical meaning of the prompt requirement that intermediate-CA changes should not break authentication as long as the new issuer is trusted.

Previous: [Chapter 4 - Production guidance and configuration direction](04-production-guidance.md)

Next: [Chapter 6 - What to build next](06-what-to-copy-next.md)
