# GSA Gateway — Operational Runbook

Universal LLM-governance control plane. This runbook covers deploy, configuration,
scaling, incident response, and rollback. It assumes the container image built from
the included `Dockerfile`.

## 1. Configuration

All operational knobs are environment variables (see `.env.example`). The image
reads them at startup via `config.py`. Key ones:

| Variable | Purpose | Prod requirement |
|---|---|---|
| `GSA_ENV` | `dev`/`staging`/`prod` | `prod` (refuses unsigned tokens) |
| `GSA_SECRET_KEY` | HMAC attestation signing key | **required**, from a secret manager |
| `GSA_JWT_PUBLIC_KEY_PATH` | RS256 public key (PEM) | **required** for real auth |
| `GSA_JWT_ISSUER` / `GSA_JWT_AUDIENCE` | JWT validation | set to your IdP values |
| `GSA_AUDIT_BACKEND` | `memory`/`sqlite`; any other value is rejected | `sqlite` (required when `GSA_ENV=prod`) |
| `GSA_AUDIT_DB_PATH` | audit DB file | on a persistent volume |
| `GSA_RATE_LIMIT_*` | per-tenant token bucket | tune to plan tiers |

In `prod`, unsigned/dev tokens are rejected: a JWT public key MUST be configured.

## 2. Deploy

### Local / staging (docker-compose)
```
export GSA_SECRET_KEY=$(openssl rand -hex 32)
docker compose up --build
# gateway on :8000, prometheus on :9090
```

### Production (container platform / k8s)
1. Provision the HMAC key and JWT public key in your secret manager; mount them.
2. Set `GSA_ENV=prod`, `GSA_AUDIT_BACKEND=sqlite`, volume for `/data`.
3. Deploy the image; wire `/metrics` into Prometheus (see `prometheus.yml`) and load
   `alerts.yml`.
4. Verify readiness: `GET /health` → `{"status":"ok", ...}`; `GET /api/version`.

## 3. Health & observability

- **Liveness/readiness:** `GET /health` — reports substrate health, circuit state,
  and the adaptive risk threshold. Non-200 or `circuit: open` ⇒ unhealthy.
- **Metrics:** `GET /metrics` (Prometheus). Watch: `gsa_circuit_state`,
  `gsa_health_composite_risk`, `gsa_observed_fdr`, `gsa_risk_threshold`,
  `gsa_request_latency_ms`, `gsa_rate_limited_total`.
- **Alerts:** shipped in `alerts.yml` (circuit open, regressive health, FDR drift,
  sustained rate limiting).

## 4. Incident response

### Circuit breaker OPEN (`gsa_circuit_state == 2`)
- Meaning: the upstream model endpoint has failed `GSA_CB_FAILURE_THRESHOLD` times;
  the gateway is fast-failing with 503 to protect itself.
- Check upstream model health/latency first. The breaker auto-trials recovery after
  `GSA_CB_RECOVERY_TIMEOUT_S`. If upstream is healthy and it still trips, raise the
  threshold/timeout via env and roll the deployment.

### Health REGRESSIVE / STRESSED (`gsa_health_composite_risk > 0.8`)
- Inspect the regime via `/health` and recent traces (`GET /api/v3/traces`).
- ATTACKED ⇒ a spike in blocked/high-risk traffic (often a real attack or a noisy
  tenant) — consider tightening the relevant policy or rate limits for that tenant.
- STRESSED/CASCADING ⇒ latency/queue/failure pressure — scale out (section 5).

### FDR drift (`gsa_observed_fdr > 0.10`)
- The gate is over-blocking (too many false alarms). The adaptive controller will
  raise the threshold automatically as ground-truth feedback arrives via
  `POST /api/v3/feedback`. If no feedback is being supplied, wire that pipeline.

### Auth failures (401 spike)
- Verify the JWT public key, issuer, and audience match the IdP. Rotate the public
  key by updating `GSA_JWT_PUBLIC_KEY_PATH` and rolling the deployment.

## 5. Scaling

- The gateway is stateless **except** for per-instance adaptive state (circuit
  breaker, rate-limit buckets, FDR window, trajectory history) and the audit store.
- Horizontal scale today: run N replicas behind a load balancer with **sticky-free**
  routing for stateless request handling. The only persistent backend today is
  SQLite, which is per-instance: a **shared audit store** (e.g. Postgres) so the
  ledger/traces are unified across replicas is not implemented yet.
- Known limitation: rate limiting and FDR state are per-instance. For exact global
  quotas/threshold-sharing across replicas, move those to a shared store (e.g. Redis)
  — tracked as a follow-up.

## 6. Policy operations

- **Swap a policy** without redeploying core: call `Gateway.set_policy(...)` (hot
  reload) or restart with a different registered policy.
- **Stack policies** (defense in depth): compose via `PolicyRegistry.compose(...)`;
  each member gets its own adaptive threshold.
- **Validate a policy before shipping:** run `validate_policy(policy, cases)` (see
  `policy_api.py`) — no gateway needed. Gate deploys on conformance pass.

## 7. Rollback

- Image rollback: redeploy the previous image tag (`gsa-gateway:<prev>`); config is
  external so no data migration is needed for a pure version rollback.
- Policy rollback: re-register/hot-swap the previous policy version. The audit record
  stamps `policy_name@version` for every decision, so you can confirm exactly which
  policy version adjudicated any trace via `GET /api/v3/replay/{trace_id}`.
- Audit store: the chain is append-only and tamper-evident (`verify_chain`); never
  edit it. A bad deploy does not corrupt prior records.

## 8. Backup & retention

- Back up the audit DB volume (`/data`) on your standard schedule. The chain is
  hash-linked, so integrity is verifiable after restore via the genesis-to-tip walk.
- The schema is two append-only tables (`audit_chain`, `traces`). A Postgres
  backend is not implemented; SQLite is the only persistent option.
