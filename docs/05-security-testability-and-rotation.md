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

## Enterprise hardening checklist

Use this checklist when preparing an mTLS implementation for production. Items marked ✅ are implemented in the repo's current code. Items marked 📄 are documented but not yet coded. Items marked ⬚ are recommendations for your own implementation.

### Certificate generation

- ✅ Use ECDSA P-256 or stronger for all key pairs (`internal/pki/simple.go` and `internal/pki/enterprise.go`)
- ✅ Generate cryptographically random serial numbers (`randomSerial()` in `cert.go`)
- ✅ Set Subject Key Identifier on all certificates (`computeSKID()` in `cert.go`)
- ✅ Set Authority Key Identifier on leaf certificates pointing to the issuing CA
- ✅ Include DNS SANs for service FQDNs (`mtlsenterprise` and `mtlsenterprisetpm` scenarios)
- ✅ Use separate EKU per role: `ServerAuth` only on server certs, `ClientAuth` only on client certs (`mtlsenterprise` and `mtlsenterprisetpm`)
- ✅ Use an intermediate CA for leaf issuance, not the root directly (`mtlsenterprise` and `mtlsenterprisetpm` scenarios)

### Key protection

- ✅ Restrict private key file permissions to owner-only: 0600 (`WriteKey()` in `cert.go`)
- ✅ Support TPM-backed non-exportable client keys (`mtlstpm` scenario)
- ✅ Use `crypto.Signer` interface for key abstraction (`internal/client.NewMTLSWithSigner`)
- ⬚ Restrict cert store private key ACLs to the service account identity
- 📄 Support non-exportable server keys via Windows cert store (proposed `mtlstpmserverstore`)
- 📄 Support Azure Key Vault for cloud-hosted key material (proposed `mtlsazurekv`)

### TLS configuration

- ✅ Set explicit `MinVersion: tls.VersionTLS12` on all `tls.Config` structs
- ✅ Require and verify client certificates on mTLS servers (`ClientAuth: tls.RequireAndVerifyClientCert`)
- ✅ Use separate trust pools for server validation and client validation
- ⬚ Consider `MinVersion: tls.VersionTLS13` if all clients support it
- ⬚ Avoid `InsecureSkipVerify` except in controlled test environments

### Server hardening

- ✅ Set `ReadTimeout`, `WriteTimeout`, and `IdleTimeout` on `http.Server`
- ✅ Use graceful shutdown via `server.Shutdown(ctx)` instead of `server.Close()`
- ⬚ Set `MaxHeaderBytes` to prevent oversized request headers
- ⬚ Add rate limiting or connection limits for production traffic
- ⬚ Log and monitor rejected TLS handshakes

### Trust management

- ✅ Distribute CA certificates as separate public files per party (ownership boundaries in `mtlsfiles`)
- ✅ Test rejection of certificates from untrusted CAs (negative-path tests in all mTLS scenarios)
- 📄 Plan CA rollover: trust new CA → reissue leaves → retire old CA (Chapter 5 rotation guidance)
- ⬚ Version and audit trust bundle changes
- ⬚ Monitor certificate expiry and alert before renewal deadline

### Certificate rotation

- 📄 Issue new certificate before old one expires
- 📄 Import alongside old during migration window
- 📄 Keep runtime certificate selection stable
- 📄 Retire old certificate after successful rollout
- ⬚ Implement `tls.Config.GetCertificate` callback for hot-reloading without restart

### Observability

- ✅ Print certificate details at connection time (Subject, Issuer, Serial, SKID/AKID)
- ✅ Print TLS version and cipher suite per connection
- ⬚ Use structured logging (`log/slog`, `zap`, or similar) instead of `fmt.Printf`
- ⬚ Export certificate expiry as a metric (Prometheus gauge or similar)
- ⬚ Log client certificate thumbprints for audit trails

### Testing

- ✅ Integration tests that exercise the full TLS/mTLS handshake
- ✅ Use `t.TempDir()` for file-based test isolation
- ✅ Test untrusted client rejection as first-class test cases
- ⬚ Add unit tests for certificate generation edge cases
- ⬚ Add concurrent client stress tests
- ⬚ Test certificate expiry handling

Previous: [Chapter 4 - Production guidance and configuration direction](04-production-guidance.md)

Next: [Chapter 6 - What to build next](06-what-to-copy-next.md)
