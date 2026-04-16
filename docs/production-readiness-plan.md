# ZTTS Production Readiness Plan

This document identifies the gaps between the current implementation and a production-ready deployment, organized into phases by priority.

Items marked ~~strikethrough~~ have been completed.

---

## Phase 1: Security Hardening (Critical)

### ~~1.1 mTLS claims lack JTI~~ ✅
**Resolved:** mTLS-derived claims now include a synthetic JTI (SHA-256 cert fingerprint + nanosecond timestamp) and a 5-minute expiry, so revocation and replay protection apply uniformly.

### 1.2 Key rotation support
**Problem:** Signing keys and trusted verification keys are loaded once at startup. Rotating keys requires a full service restart with no overlap period.

**Action:** Implement JWKS endpoint for verification keys and key-id (`kid`) header matching on verification. For signing, support loading multiple keys per profile with an active/passive designation so the old key can still verify while the new key signs.

### ~~1.3 Auth package test coverage~~ ✅
**Resolved:** The `auth` package now has unit tests covering Signer, middleware, certificate loading, and mTLS authentication. Coverage: 66.7%.

### ~~1.4 TLS configuration hardening~~ ✅
**Resolved:** `tls.Config` now explicitly sets `MinVersion: tls.VersionTLS12` in all TLS paths (mTLS and plain TLS).

---

## Phase 2: Operational Readiness

### ~~2.1 Distributed-capable replay and revocation~~ ✅ (Partial)
**Resolved (interfaces):** `TokenService` now depends on `RevocationChecker`, `ReplayChecker`, and `PolicyAuthorizer` interfaces. Swapping in Redis-backed implementations requires only implementing these interfaces.

**Remaining:** No Redis implementation yet. File-backed store and in-memory guard are the only backends.

### 2.2 Metrics and observability
**Problem:** No Prometheus metrics, no OpenTelemetry tracing, no health check beyond a static `{"status":"ok"}`.

**Action:**
- Export Prometheus metrics: `ztts_token_requests_total` (by profile, outcome), `ztts_token_latency_seconds`, `ztts_revocations_total`, `ztts_active_revocations`, `ztts_replay_rejections_total`
- Add OpenTelemetry trace spans to `ProcessRequest` pipeline stages
- Enrich `/health` to check revocation store accessibility and signing key availability

### 2.3 Rate limiting
**Problem:** No rate limiting on any endpoint. A compromised client can hammer the token endpoint.

**Action:** Add per-client-IP rate limiting middleware using a token bucket (e.g., `golang.org/x/time/rate`). Make limits configurable per endpoint.

### 2.4 Request/response logging and audit trail
**Problem:** `slog` messages go to stderr. There is no persistent, tamper-evident audit trail of token issuances and revocations.

**Action:** Add an audit log output (structured JSON lines to a dedicated file or log sink) capturing: timestamp, action, profile, subject, issuer, JTI (issued/revoked), client IP, outcome. Separate operational logs from audit logs.

---

## Phase 3: Operational Flexibility

### 3.1 Policy hot-reload
**Problem:** SPOCP rules are loaded once at startup. Any rule change requires a restart, causing a brief outage.

**Action:** Implement `SIGHUP`-triggered reload: load new rules into fresh engines, atomic swap of the authorizer's engine map. Alternatively, use `fsnotify` for automatic file-watch reload.

### 3.2 Environment variable substitution in config
**Problem:** Secrets (signing key paths) are stored as literal strings in YAML. This makes container deployment awkward since secrets must be baked into config files.

**Action:** Support `${ENV_VAR}` syntax in YAML string values, resolved at load time. Alternatively, support `file://` references or direct environment variable config overrides for sensitive fields.

### 3.3 OpenAPI specification
**Problem:** No formal API documentation. Consumers rely on reading handler code or the specs.md.

**Action:** Write an OpenAPI 3.0 spec covering all endpoints, request/response schemas, authentication requirements, and error codes. Generate it from code annotations or maintain manually alongside handlers.

### ~~3.4 Admin bootstrap~~ ✅
**Resolved:** Admin bootstrap has been removed. All authentication is via mTLS client certificates.

---

## Phase 4: Testing and CI

### ~~4.1 Integration tests~~ ✅
**Resolved:** 8 integration tests using `httptest.NewServer` exercise the full HTTP pipeline:
- Full token exchange round-trip (authenticate → request → verify response token)
- Token renewal flow
- Revocation: issue → revoke → reject
- Replay: issue → replay same token → reject
- Scope restriction enforcement
- Unauthenticated and invalid token rejection
- Registered claim protection (verifies `iss` cannot be overwritten via claims)

### 4.2 Fuzz testing
**Problem:** No fuzz testing for JSON parsing, S-expression construction, or PEM parsing.

**Action:** Add Go native fuzz tests (`func FuzzXxx`) for:
- `json.Decode` of `TokenRequest` (malformed JSON)
- `BuildQueryElement` with adversarial claim values
- `loadPublicKeys` / `parsePrivateKey` with malformed PEM

### ~~4.3 CI pipeline~~ ✅
**Resolved:** GitHub Actions workflows configured:
- `ci.yml` — build, test, vet, lint, format check on push/PR
- `release.yml` — tag-triggered release builds
- `codeql.yml` — weekly security analysis

---

## Phase 5: Deployment

### ~~5.1 Container image~~ ✅
**Resolved:** Multi-stage Dockerfile added (builder + alpine runtime). Docker-publish workflow publishes to `ghcr.io`.

### 5.2 Configuration schema validation
**Problem:** Config validation is basic (required field checks). No schema-level validation for durations, paths, key formats.

**Action:** Validate that `signing_key_file` is a readable PEM file at startup. Validate `rules_dir` contains at least one `.rules` file. Validate `validity` is within reasonable bounds. Emit warnings for missing `scopes` (unrestricted profile).

### 5.3 Documentation
**Problem:** Only `specs.md` and the ADR exist. No operator guide, no deployment runbook.

**Action:** Write:
- Operator guide: deployment, configuration reference, key generation, rule authoring
- Runbook: startup checklist, monitoring alerts, incident response for key compromise, token revocation procedures
- Architecture overview diagram (for non-ADR audience)
