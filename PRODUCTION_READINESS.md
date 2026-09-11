# GSA: Universal Governance Control Plane
## Production Readiness Assessment

**Date:** June 2026  
**Overall Score:** 7.31/10  
**Verdict:** **STAGING / PRE-PRODUCTION (gated launch)**

---

## Executive Summary

GSA is a **universal LLM-governance substrate** with a clean policy-adapter seam. Domain expertise (what is risky, what output is acceptable) lives in pluggable policies; the core owns the universal mechanism (audit, attestation, health scoring, adaptive control, rate limiting, API, deployment).

The system is **ready for staging deployment** under the following conditions:
- Single policy, single-instance deployment  
- Operator monitoring of health thresholds
- Ground-truth feedback loop for adaptive threshold tuning
- Bearer-token authentication (no real token verification yet)
- Ledger stored in memory (no restart durability)

**It is NOT ready for production without:**
- Persistent audit ledger + replay protection
- OIDC/JWT token verification + secret manager
- Multi-policy composition or hot-reload
- Deployment infrastructure (Docker, k8s, runbooks)
- Real operator runbooks and alert thresholds

---

## Dimension Scores (Weighted Average = 7.31/10)

### 1. **Policy-Seam Clarity & Isolation** — 9/10 ⭐ READY
**Weight:** 15%

A 2-method interface (`assess_input`, `inspect_output`) exposed as a structural Protocol. Zero domain rules in the core — all keywords, injection patterns, and style checks live in policy adapters.

**Why 9 not 10:**
- No published "authoring a policy" guide/template
- `PolicyContext` is loosely typed (should be a TypedDict schema)

**Evidence:**
- `policy_api.py` imports nothing from `gsa_gateway.py` (verified by subprocess test)
- `example_policies.py` contains working BaselinePolicy + FinancialPIIPolicy authored against seam alone
- `test_policy_seam.py` demonstrates domain expert authoring MedicalRedactionPolicy in-test, validating to 100% without core

**Status:** ✅ SHIPPING AS-IS. Strongest part of the system.

---

### 2. **Policy Testability & Conformance** — 8/10 READY
**Weight:** 12%

A `validate_policy()` harness runs policies against labeled `InputCase`/`OutputCase` batteries, reporting accuracy + precision + recall — using ONLY the seam (no gateway, no async, no network).

**Why 8 not 10:**
- No golden-corpus / regression test fixtures
- No property-based / adversarial fuzzing
- No CI template for domain experts

**Evidence:**
- 8 passing seam tests
- MedicalRedactionPolicy example runs to 100% accuracy
- Hot-swap tests prove core invariants hold for any policy

**Status:** ✅ READY FOR AUTHORING. Production-grade policies should include fuzz-tested golden corpora.

---

### 3. **Policy Composition & Lifecycle** — 5/10 GATED
**Weight:** 8%

Policies carry name/version/domain; hot-swap at Gateway construction is proven; non-interference is proven.

**Why 5 not 8:**
- No multi-policy composition (can't stack PII + domain policy with precedence)
- No runtime hot-reload (swap only at construction)
- One global FDR threshold controller
- No policy registry / discovery

**Evidence:**
- `test_policy_seam.py::test_swapping_policy_changes_only_the_decision` proves hot-swap works
- `test_policy_seam.py::test_core_invariants_hold_for_every_policy` proves core stability

**Status:** ⚠️ GATED — SINGLE POLICY ONLY for v1. Multi-policy stacking is top v2 item.

---

### 4. **Execution & Reliability** — 8/10 READY
**Weight:** 13%

Async attestation pool with bounded queue; 3-state circuit breaker (fast-fail 503 / half-open recovery / 502 on real errors); structured responses.

**Evidence:**
- 43 passing pytest tests (35 gateway + 8 seam)
- 13-check self-test, all green
- Load test: 3,544 req/s at concurrency 100, p99 ~35ms, **0 errors**
- Self-test [10]: circuit breaker lifecycle verified

**Why 8 not 10:**
- Per-instance state; multi-replica needs Redis or similar
- No chaos/fuzz; no CI pipeline

**Status:** ✅ READY FOR SINGLE-INSTANCE, with operator monitoring of circuit breaker.

---

### 5. **Auditability of Policy Execution** — 7/10 MONITOR
**Weight:** 12%

Hash-linked, tamper-evident ledger (SHA-256 chain) + deterministic forensic attestation (explicit timestamp + nonce, constant-time verify) + tenant-scoped replay.

**Evidence:**
- Self-test [6]: audit chain verification (pre=True, post-tamper=False)
- Self-test [9]: attestation verify (good=True, tampered=False)
- `/api/v3/replay/{trace_id}` is tenant-scoped
- `/api/v3/feedback` feeds ground truth to FDR controller

**Why 7 not 9:**
- In-memory only; lost on restart (needs PostgreSQL)
- Audit record doesn't stamp policy NAME/VERSION
- No external time-authority anchoring

**Status:** ⚠️ STAGING. Production requires: Postgres persistence, policy version stamping, optional external anchor.

---

### 6. **Operational Health & Adaptive Control** — 9/10 READY ⭐
**Weight:** 12%

Two universal control loops:
1. **URE regime engine:** 6 regimes (NOMINAL, ADAPTING, RECOVERING, STRESSED, ATTACKED, CASCADING). Energy from 6 normalized pressures. All regimes reachable; no UNKNOWN dead zone.
2. **FDR controller:** Tunes risk-block threshold from ground-truth feedback. Threshold actually drives decision.

**Evidence:**
- Self-test [8]: idle→NOMINAL/NEUTRAL, under-load→ATTACKED/RISK_INCREASING
- Engine calibration: idle=0.0 energy, all 6 regimes reachable via sweep
- Self-test [12]: FDR moves threshold (0.8→0.92 on false alarms, 0.8→0.60 on clean)
- Self-test [13]: threshold feeds decision (identical score flips with threshold)
- Prometheus metrics: energy, health, threshold, FDR

**Why 9 not 10:**
- Thresholds tuned for synthetic loads; real traffic may require tuning
- Per-instance state; no shared state for multi-replica

**Status:** ✅ READY AS-IS. Thresholds are operator-tunable knobs post-deploy.

---

### 7. **Authentication & Multi-Tenancy** — 6/10 MONITOR
**Weight:** 10%

Bearer-token auth + per-tenant rate limiting (429 + Retry-After) + tenant-scoped replay/feedback.

**Evidence:**
- Self-test [11]: rate limiter (capacity 5, burst → throttle, 429 returned)
- `/api/v3/replay` and `/api/v3/feedback` check tenant_id
- `Depends(authed_tenant)` on all protected routes

**Why 6 not 8:**
- No token SIGNATURE verification (needs OIDC/JWT RS256 or mTLS)
- Secret is process-level, not rotated
- Rate-limit buckets per-instance; shared ledger allows timing attacks

**Status:** ⚠️ STAGING ONLY. Production requires: OIDC/JWT RS256, secret manager, rotation policy.

---

### 8. **API & Integration** — 8/10 READY
**Weight:** 8%

Typed Pydantic schemas + explicit versioning (API_VERSION + X-API-Version header + `/api/version` discovery + Deprecation/Sunset headers) + paginated `/api/v3/traces` + `/api/v3/feedback`. Policy injected via dependency injection.

**Endpoints:**
- `POST /api/v3/evaluate` — process request
- `GET /api/v3/replay/{trace_id}` — retrieve past decision
- `GET /api/v3/traces?limit=N&offset=M` — list traces (tenant-scoped)
- `POST /api/v3/feedback` — supply ground truth
- `GET /api/version` — version discovery
- `GET /health` — readiness + substrate + circuit

**Why 8 not 10:**
- Pre-1.0 surface; no OpenAPI contract test in CI
- No container image / SDK

**Status:** ✅ READY FOR PRODUCTION, with: backwards-compat commitment through v3.x, OpenAPI contract tests in CI.

---

### 9. **Deployment & Operations** — 4/10 GATED
**Weight:** 10%

Pure-Python FastAPI service (`python3 gsa_gateway.py` or uvicorn). That's it.

**Why 4 not 7:**
- No Dockerfile / docker-compose / k8s / Terraform
- No externalized config (constants in-source)
- No runbooks, dashboards, alert rules, CI pipeline

**Status:** ❌ NOT PRODUCTION READY. Pure engineering: Containerize, externalize config, write runbooks, Grafana dashboards, alert rules, CI pipeline.

---

## What Moves the Score to 8.0 (PRODUCTION READY)

**Four pure-engineering items** (no domain work):

| Dimension | Current | Target | Effort | Delta | Path |
|-----------|---------|--------|--------|-------|------|
| **Policy Composition** | 5 | 8 | 2–3 weeks | +0.24 | Multi-policy stacking + per-policy thresholds + registry |
| **Deployment & Ops** | 4 | 7 | 1–2 weeks | +0.30 | Dockerfile + compose + runbooks + CI |
| **Auth & Multi-Tenancy** | 6 | 8 | 1 week | +0.20 | OIDC/JWT + secret manager |
| **Auditability** | 7 | 8 | 1–2 weeks | +0.12 | Postgres + policy version stamping |

**Running total:** 7.31 → 7.55 → 7.85 → 8.05 → **8.17/10**

---

## Critical Path to 8.0 (4–5 weeks)

**Week 1–2:** Deploy & Auth
- Containerize (Dockerfile, docker-compose, externalize config)
- Add OIDC/JWT token verification
- Integrate secrets manager

**Week 2–3:** Audit & Persistence
- Back ledger/traces to PostgreSQL
- Stamp policy.name/version in each record
- Add pre-flight migration tooling

**Week 3–4:** Policy Composition
- Implement multi-policy stacking with precedence
- Per-policy threshold isolation
- Policy registry (YAML loader or dynamic import)

**Week 4–5:** Operations
- Grafana dashboards (energy, regime, health, FDR, circuit)
- Alert rules (circuit open, health regressive, FDR drift, rate limit)
- Runbooks (deployment, scaling, incident response, rollback)
- CI pipeline (lint, pytest, contract tests, build, push)

---

## Key Architectural Wins

✅ **Policy-adapter seam is genuinely isolated.** Domain expert can author + validate a policy with ONLY `policy_api.py` imported — no gateway, no network, no async.

✅ **Core invariants hold for any policy.** Audit, attestation, health, control, circuit breaker, rate limiting are policy-agnostic. Proven.

✅ **URE health engine is correctly calibrated.** Idle=NOMINAL/0.0 energy, attack=ATTACKED/RISK_INCREASING, all 6 regimes reachable, no UNKNOWN dead zone.

✅ **Adaptive threshold actually drives decisions.** FDR loop moves the threshold; threshold drives blocking. Not ceremonial.

✅ **No domain rules in the core.** Keywords, injection patterns, style checks all in policies. Gateway is domain-agnostic.

---

## What This System Is NOT

❌ **Not a domain detector.** Governance substrate. Detection is the policy's job.

❌ **Not a production security appliance yet.** Lacks persistence, real auth, multi-replica state, deployment infrastructure.

❌ **Not a healthcare product.** No EHR, FHIR, dose checking, FDA/HIPAA compliance.

❌ **Not a multi-policy composition engine (v1).** Single policy only; v2 adds stacking.

---

## Recommended Launch Strategy

**Phase 1: Staging (4–6 weeks)**
- Non-production environment with single policy
- Collect ground-truth feedback to tune URE + FDR
- Exercise policy-feedback loop
- Operator monitors /health, /metrics, circuit breaker

**Phase 2: Early Production (6–12 weeks)**
- Full deployment infrastructure (Docker, k8s, secrets manager)
- Real OIDC/JWT token verification
- Persistent ledger (PostgreSQL)
- Operator runbooks + Grafana + alert rules
- Multi-policy composition ready (v2 launch gating)

**Phase 3: Multi-Policy (12–24 weeks)**
- Enable policy composition (stack + precedence + registry)
- Support multiple customer policies simultaneously
- Per-policy adaptive thresholds
- Policy hot-reload (optional; restart-based sufficient for v1)

---

## DO NOT

**Do NOT add a semantic "safety classifier" to the core.**

The seam exists so detection intelligence lives in policies, not in the gateway. If you build a safety model, it belongs in a `SemanticRiskPolicy` that plugs into the seam — not in the core. That keeps the system composable and lets multiple safety approaches coexist (keyword + semantic, keyword only, domain-specific heuristics, etc.).

---

**Assessment prepared:** June 2026  
**System version:** GSA v3.1 (universal control plane, policy-seam architecture)  
**Test coverage:** 43 pytest + 13 self-test, all green  
**Load test:** 3,544 req/s, p99 35ms, 0 errors at concurrency 100
