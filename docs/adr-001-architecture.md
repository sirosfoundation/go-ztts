# ADR-001: Zero Trust Token Service Architecture

**Status:** Accepted  
**Date:** 2025-07-24  
**Deciders:** SIROS Foundation Engineering

## Context

The SIROS ecosystem requires a service that enables policy-controlled JWT token exchange. Clients authenticate with an existing JWT (or mTLS certificate) and request a new JWT governed by a named profile. The service must enforce fine-grained authorization rules, support token lifecycle management (revocation, replay protection), and provide an administrative bootstrap mechanism for initial credential provisioning.

The design is captured in [docs/specs.md](docs/specs.md).

## Decision

### Token Exchange Model

The service implements a single-endpoint token exchange pattern (`POST /token`). An authenticated client submits a JSON request specifying:

- `profile` — the name of the token profile to issue against
- `scopes` — requested scopes (validated against profile-allowed set)
- `userid` — delegated user identity (optional)
- `tenant` — tenant context (optional)
- `audience` — explicit target audience (optional)

The service validates the incoming credential, assembles authenticated claims from both the verified token and the request body, evaluates an authorization policy, and—if permitted—issues a new JWT. The outgoing token carries custom claims (`profile`, `scopes`, `userid`, `tenant`) in a `ZTTSClaims` type that extends `jwt.RegisteredClaims`.

The outgoing `sub` is always the incoming client identity (from the verified token's `sub`). The `userid` field is a separate custom claim for delegation, keeping cryptographic identity and delegated user identity distinct. Audience is determined by a fallback chain: explicit request field → incoming `sub` → incoming `iss`.

### Authentication

Two authentication mechanisms are supported, implemented as HTTP middleware with fallback:

1. **JWT Bearer** (primary) — The `Authorization: Bearer <token>` header is validated against a configured set of trusted public keys. The `Verifier` tries each key sequentially and accepts the first successful validation. Supported algorithms: RS256, ES256, EdDSA (RSA, ECDSA, Ed25519).

2. **mTLS client certificate** (fallback) — If no Bearer token is present but a verified TLS client certificate exists, claims are synthesized from the certificate: `sub` from CommonName, `aud` from the first DNS SAN, `iss` from the first URI SAN. mTLS is configured at server level via `tls.Config.ClientCAs` with `VerifyClientCertIfGiven`.

### Authorization via SPOCP

Authorization decisions are delegated to SPOCP (Simple Policy Control Protocol) rule engines via the `go-spocp` library. Each token profile has its own `AdaptiveEngine` loaded at startup from `.rules` files in a designated directory. The engines are immutable after construction.

For each token request, the service constructs an S-expression query from the assembled claims:

```
(ztts (profile <name>) (sub <subject>) (iss <issuer>) (aud <audience>) (scopes <s1> <s2> ...) (userid <uid>) (tenant <tid>))
```

The engine evaluates this against its rule set and returns an allow/deny decision. Rules are authored in SPOCP's human-readable "advanced" format.

This approach was chosen because:
- SPOCP provides a well-defined, formally grounded access control language
- S-expression matching supports structural patterns (wildcards, ranges, prefix sets)
- Rule files are human-readable and auditable
- Per-profile engines avoid cross-profile policy interference

### Profile-Based Configuration

Token profiles are the central organizational unit. Each profile defines:
- `rules_dir` — directory of SPOCP rule files
- `validity` — token lifetime (`time.Duration`)
- `signing_key_file` — PEM-encoded private key for signing issued tokens
- `allow_renewal` — whether a token of this profile can be exchanged for another of the same profile
- `scopes` — whitelist of permitted scopes (empty = unrestricted)

Configuration is YAML-based with an optional split: profiles can be loaded from a separate file (`--profiles` flag), enabling independent profile management.

### Token Signing

Each profile has its own `Signer` (created at startup from its `signing_key_file`). The signer auto-detects the key type and selects the appropriate algorithm (RS256 for RSA, ES256 for ECDSA, EdDSA for Ed25519). This enables per-profile key isolation—different profiles can use different key types and rotation schedules.

All issued tokens include a UUID-based JTI, standard temporal claims (`iat`, `nbf`, `exp`), and the custom ZTTS claims.

### Revocation and Replay Protection

**Revocation:** A file-backed `Store` tracks revoked JTIs with metadata (revocation time, original expiry, reason). Revoked entries are persisted as JSON on every mutation. A background goroutine periodically cleans up entries whose original token has expired. Persistence is performed under the write lock to prevent data races.

**Replay protection:** An in-memory `Guard` records every JTI seen for the first time and rejects subsequent presentations of the same JTI. Entries expire based on the original token's `exp` claim and are cleaned up periodically. Incoming tokens without a JTI are rejected outright.

Both mechanisms are checked early in the `ProcessRequest` pipeline: revocation check → replay check → claim assembly → authorization → token issuance.

### Bootstrap Mechanism

An administrative endpoint (`POST /admin/bootstrap`) allows creation of initial tokens without an incoming JWT. Authentication uses API keys compared with `crypto/subtle.ConstantTimeCompare`. Bootstrap tokens carry only standard registered claims (no custom claims). This enables the trust bootstrapping flow described in the spec:

1. Admin issues a bootstrap token for a service audience
2. Service uses this token to request a `bootstrap-renewal` token (renewal permitted)
3. Service periodically renews its credential to maintain continuous authentication
4. Service uses its credential to request purpose-specific tokens (e.g., `service-access`)

### HTTP Layer

The handler layer uses Go's `net/http.ServeMux` with:
- `http.MaxBytesReader` (1 MB limit) on all request bodies to prevent resource exhaustion
- Case-insensitive Bearer token extraction via `strings.EqualFold`
- Structured error responses via a typed `ErrorResponse` with `json.Encoder`
- Health check endpoint at `GET /health`
- Graceful shutdown with a 10-second timeout on `SIGINT`/`SIGTERM`

### Structured Logging

All operations use `log/slog` with key-value pairs for structured, machine-parseable logging. Token issuances, denials, revocations, and errors are logged with relevant context (profile, subject, JTI, reason).

## Consequences

### Benefits

- **Separation of concerns:** Authentication, authorization, token issuance, and lifecycle management are in independent packages with minimal coupling.
- **Policy as data:** Authorization rules live outside the binary in human-readable files, enabling policy changes without redeployment.
- **Per-profile isolation:** Each profile has its own signing key, rule engine, and configuration, preventing unintended policy leakage.
- **Bootstrap self-sufficiency:** The admin → bootstrap → renewal flow allows services to maintain long-lived authentication without external credential management.
- **Minimal dependencies:** Four external dependencies (jwt, uuid, go-spocp, yaml).

### Trade-offs

- **Single-process design:** Revocation and replay state are process-local (file-backed and in-memory respectively), which limits horizontal scaling.
- **Startup-only policy loading:** Rule changes require a service restart.
- **Sequential key verification:** The JWT verifier tries keys linearly; with many trusted keys this could add latency.
- **No key rotation signaling:** Signing key rotation requires configuration change and restart.

## Package Structure

```
go-ztts/
├── cmd/ztts/main.go           # Entry point, initialization, graceful shutdown
├── pkg/
│   ├── types/types.go         # TokenRequest, ZTTSClaims, TokenResponse, ErrorResponse, AuthenticatedClaims
│   ├── config/config.go       # YAML config loading and validation
│   ├── auth/
│   │   ├── auth.go            # JWT Verifier (multi-key) and Signer (per-profile)
│   │   └── middleware.go      # HTTP auth middleware with JWT + mTLS fallback
│   ├── authz/authz.go         # SPOCP-based per-profile authorization engine
│   ├── revocation/store.go    # File-backed JTI revocation store
│   ├── replay/guard.go        # In-memory JTI replay detection
│   ├── service/service.go     # Core token processing logic
│   └── handler/handler.go     # HTTP handlers (/token, /revoke, /admin/bootstrap, /health)
├── examples/
│   ├── config.yaml            # Example configuration with 4 profiles
│   └── rules/                 # Example SPOCP rule files per profile
└── docs/
    └── specs.md               # Original service specification
```

## Request Processing Pipeline

```
Client Request
     │
     ▼
┌─────────────────┐
│  HTTP Handler    │  MaxBytesReader, method check, JSON decode
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Auth Middleware │  JWT verification (or mTLS fallback)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  TokenService    │
│  .ProcessRequest │
│                  │
│  1. Require JTI  │
│  2. Revocation   │  ← revocation.Store
│  3. Replay       │  ← replay.Guard
│  4. Claim build  │
│  5. Renewal gate │
│  6. Scope check  │
│  7. SPOCP authz  │  ← authz.Authorizer
│  8. Sign token   │  ← auth.Signer
└────────┬────────┘
         │
         ▼
   TokenResponse (JWT + metadata)
```
