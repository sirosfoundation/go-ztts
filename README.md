[![Go Reference](https://pkg.go.dev/badge/github.com/sirosfoundation/go-ztts.svg)](https://pkg.go.dev/github.com/sirosfoundation/go-ztts)
[![CI](https://github.com/sirosfoundation/go-ztts/actions/workflows/ci.yml/badge.svg)](https://github.com/sirosfoundation/go-ztts/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/sirosfoundation/go-ztts)](https://goreportcard.com/report/github.com/sirosfoundation/go-ztts)
[![codecov](https://codecov.io/gh/sirosfoundation/go-ztts/branch/main/graph/badge.svg)](https://codecov.io/gh/sirosfoundation/go-ztts)
[![License](https://img.shields.io/badge/License-BSD_2--Clause-blue.svg)](https://opensource.org/licenses/BSD-2-Clause)

# go-ztts

**Zero Trust Token Service** — a policy-controlled JWT token exchange service built on [SPOCP](https://github.com/sirosfoundation/go-spocp) authorization rules with mTLS client authentication.

## Overview

`go-ztts` authenticates clients via mTLS, evaluates per-profile SPOCP authorization rules against certificate metadata, and issues signed JWTs when permitted. It supports:

- **mTLS client authentication** — all clients must present a valid certificate signed by a trusted CA; CRL checking is supported
- **Profile-based token issuance** — each profile has its own signing key, validity period, SPOCP ruleset, and scope restrictions
- **SPOCP authorization** — fine-grained access control using S-expression pattern matching; certificate metadata (serial, org, OU) is included in authorization queries
- **Generic custom claims** — request-defined claims (scopes, userid, tenant, etc.) flow through to authorization queries and issued tokens without code changes
- **Token lifecycle** — revocation, replay protection, and configurable renewal policies

## Quick Start

### Build

```bash
make build
```

### Run

```bash
bin/ztts -config examples/config.yaml
```

### Test

```bash
make test
```

## Configuration

Configuration is YAML-based. See [examples/config.yaml](examples/config.yaml) for a complete example.

```yaml
server:
  listen_addr: ":8443"
  tls_cert: "certs/server.crt"
  tls_key: "certs/server.key"

auth:
  ca_bundle:
    - "certs/ca.crt"
  # crl_url: "https://step-ca.example.com/1.0/crl"
  # crl_path: "certs/crl.der"
  # crl_cache_duration: 5m

profiles:
  service-access:
    rules_dir: "rules/service-access"
    validity: 1h
    signing_key_file: "keys/signing.key.pem"
    scopes:
      - "api:read"
      - "api:write"

  user-delegation:
    rules_dir: "rules/user-delegation"
    validity: 30m
    signing_key_file: "keys/signing.key.pem"

revocation:
  store_path: "data/revoked.json"
  cleanup_interval: 5m
```

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/token` | mTLS | Exchange an mTLS-authenticated request for a signed JWT |
| `POST` | `/revoke` | mTLS | Revoke a token by JTI |
| `GET` | `/health` | None | Health check |

### Token Request

```json
{
  "profile": "service-access",
  "audience": "https://api.example.com",
  "claims": {
    "scopes": ["api:read"],
    "userid": "user-42",
    "tenant": "acme"
  }
}
```

The `claims` map is generic — any key-value pairs are passed through to the SPOCP authorization query and included in the issued token. No code changes needed to add new claim types.

## Authorization Rules

Each profile has a directory of `.rules` files written in SPOCP's human-readable advanced format. SPOCP queries automatically include certificate metadata (`cert-serial`, `org`, `ou`):

```
# Allow service-access when a valid client cert is presented
(ztts (profile service-access) (cert-serial *) (org "Example Corp"))

# Only allow user delegation when userid and tenant are provided
(ztts (profile user-delegation) (cert-serial *) (org *) (userid) (tenant))
```

See [examples/rules/](examples/rules/) for working examples.

## Architecture

See [docs/adr-001-architecture.md](docs/adr-001-architecture.md) for detailed architecture decisions.

```
Client Request (mTLS)
     │
     ▼
  TLS Handshake ── CA bundle verification, CRL check
     │
     ▼
  HTTP Handler ─── MaxBytesReader, JSON decode
     │
     ▼
  Auth Middleware ── Extract cert metadata (serial, org, OU)
     │
     ▼
  TokenService
  ├─ Revocation check
  ├─ Replay check
  ├─ Claim assembly (request claims + cert metadata)
  ├─ Renewal gate
  ├─ Scope validation
  ├─ SPOCP authorization
  └─ Sign & return JWT
```

## Development

```bash
# Set up development environment (install git hooks)
make setup

# Run all checks (format, vet, test)
make check

# Coverage report
make coverage-cli

# Clean build artifacts
make clean
```

## License

BSD 2-Clause. See [LICENSE](LICENSE).
