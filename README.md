# GSA; Universal LLM Governance Control Plane

**Status:** staging candidate, not production-proven. Version 3.1.0 in the Docker tag. Last checked 2026-11-19 at commit `d85cb84`. This repo's history was rewritten after the 2026-11-15 review, which used commit `987670e` (its twin is `cc83208`). License: Apache-2.0.
**Tests:** 123 passed, 1 skipped (EXECUTED 2026-11-15, `python3 -m pytest -q` in the repo root). Earlier text here said 51 tests.
**Load figures:** the 2,800 to 3,500 requests per second figure from earlier versions of this file was not re-measured (UNKNOWN today). `loadtest.py` is the script that produced it.

> **This repository was reconstructed from archived development transcripts.**
> Every source file here was replayed from the recorded file-write operations of the
> original build sessions, then re-run and re-tested in a clean environment. The test
> counts, scorecard, and load numbers below are reproductions, not copied claims.
> See [`PROVENANCE.md`](PROVENANCE.md) for exactly what came from where and what is missing.


---

## What This Is

GSA (Governance Substrate Architecture) is a **universal LLM-governance control plane** designed to sit in front of an LLM. It enforces pluggable policies without modifying the core model. No adapter for Claude, GPT or any other provider ships in this repo: you supply your own async generator function. The app that ships (`gsa_gateway:app`, which the Docker image runs) is wired to a mock generator that returns canned text and to the reference `BaselinePolicy`, in every profile including `prod`, where it only logs a warning (EXECUTED 2026-11-15). As shipped it demonstrates the gateway; it does not govern a real model.

**The key insight:** detection is policy work, not core work. GSA provides the substrate; you write the policies.

### Core Claims (each backed by a test or a script in this repo; not independently reviewed)

- **Policy seam isolates detection from governance.** A domain expert can author and validate a policy using only `policy_api.py`; no gateway, no async, no network.

- **Core invariants hold for any policy.** Audit, attestation, health, rate limiting, circuit breaker are policy-agnostic. Tested with the Baseline, Financial and Jailbreak example policies; a test run, not a proof.

- **Multi-policy composition works.** Stack policies as defense-in-depth; each member gets its own adaptive threshold so feedback on one never moves another's.

- **Adaptive threshold converges.** The FDR loop receives ground-truth feedback and tuning the threshold actually drives decisions (not ceremonial).

- **Architecture survives real data.** Tested against 52 real jailbreaks (65% adversarial). Baseline catches 2.9% (1 of 34) after the 2026-10-28 Phoenix round, down from 5.9% because the single-word risk list was burned for blocking ordinary prompts; it is a tripwire, not a classifier. Honest gap that motivates better policies, not architectural changes.

---

## Role Within ≡TACK

- **What it is.** An LLM governance gateway: a service that sits in front of a model and applies pluggable policies to each request and response.
- **What it owns.** Policy evaluation through the seam (`policy_api.py`), a hard block on policy `hard_block`, a hash-linked SQLite audit chain with an HMAC attestation, rate limiting, a circuit breaker, and an adaptive threshold (FDR loop). In the authority matrix it enforces at its own gateway (blocks a request or response) and authenticates tenants by JWT.
- **What it contributes.** A runnable enforcement point and evidence (audit records) for requests that pass through it.
- **What it does not own.** The detection logic itself (policies do), identity issuance (an external IdP issues the JWT), custody of the audit trail beyond one SQLite file per process, and anything outside this gateway's own traffic.
- **Depends on.** `requirements.txt`. CNS is optional (`gsa_cns_connector.py`, binding only). `ure_engine.py` here is the health engine used by the gateway.
- **Depended on by.** `GSA-815` and `sentinel_os` mention it. Whether either imports it: UNKNOWN (not inspected here).
- **Verified versus declared.** Verified by tests on 2026-11-15: the gateway and policy seam behavior in the 123-test suite. Declared only: load capacity, k8s behavior, the scorecard, and the bug bounty plan below.

### Security and failure behavior

- **Dev profile is open, and is no longer the default.** Since commit `0af7ce4` (2026-11-16) an unset `GSA_ENV` means `prod` (`config.py`); before that it meant `dev`. EXECUTED 2026-11-19: with `GSA_ENV` and `GSA_SECRET_KEY` unset, the settings read `prod` and the gateway refused to start (`MissingSecretError`). The test suite sets `GSA_ENV=dev` for itself (`conftest.py`). In dev, set explicitly, `TenantAuthenticator` accepts any token of 12 or more characters and derives the tenant from its hash, and the HMAC key falls back to a labelled insecure dev key if none is set (`auth.py`). Set `GSA_ENV=staging` or `prod` and a JWT public key before exposing the service. Staging and prod refuse unsigned tokens and refuse to start without a secret key (README configuration section, `test_hardening.py`).
- The baseline policy is a tripwire, not a classifier (2.9% recall on the test set).
- One replica only: the audit ledger, rate limiter, circuit breaker and threshold are per process.
- An output the policy still rejects after retries is blocked, not released (flow step 4). An exception raised inside `assess_input` is not caught in `PolicyInputGate` (INSPECTED, `gsa_gateway.py` near line 263); it propagates to the caller. Through the HTTP layer the request gets a 500 and no ledger entry is written (EXECUTED 2026-11-15).
- **One tenant could block every tenant (fixed on the web endpoint; EXECUTED 2026-11-19).** `compute_load` drives one shared health value, and below 0.5 the gateway answers 403 to all tenants. The `/api/v3/evaluate` endpoint now accepts the field and ignores it, so a caller cannot move that value. Limits that remain: the substrate health gate is inactive for web traffic until the server measures its own pressure (for example the signing queue); code that calls `Gateway.process` directly can still pass `compute_load`; and one tenant's blocked requests still raise the shared blocked rate shown in `health` and the dashboards, which changes reporting but not who is served.
- The audit store defaults to memory (`GSA_AUDIT_BACKEND=memory`), so in dev nothing is kept after the process exits. The `prod` profile refuses to start without `sqlite` (EXECUTED 2026-11-15).

---

## Quick Start

### Local (docker-compose)

```bash
export GSA_SECRET_KEY=$(openssl rand -hex 32)
docker compose up --build
# Gateway on :8000, Prometheus on :9090
```

### Local (from source)

```bash
GSA_ENV=dev uvicorn gsa_gateway:app --port 8000
```

`GSA_ENV=dev` must be set explicitly. Unset, `GSA_ENV` means `prod`, which refuses to start without a real
`GSA_SECRET_KEY` and `GSA_AUDIT_BACKEND=sqlite`, and refuses unsigned bearer tokens.

### Production (container/k8s)

1. Mount secrets: HMAC key + JWT public key
2. Set `GSA_ENV=prod`
3. Wire `/metrics` to Prometheus
4. Load `alerts.yml` for circuit-breaker, health, FDR alerts

These steps start the bundled app, which answers with canned text from the mock generator (see What This Is). To govern a real model, embed `Gateway(your_generator, policy=your_policy)` in your own service.

See `RUNBOOK.md` for full deployment, scaling, incident response.

---

## Architecture

### The Seam

```python
from policy_api import PolicyAdapter, InputVerdict, OutputVerdict

class MyPolicy(BasePolicy):
    name = "my-policy"
    
    def assess_input(self, request: str, context: dict) -> InputVerdict:
        # Your detection logic here
        score = detect_risk(request)
        return InputVerdict(score=score, hard_block=(score >= 0.95), reasons=[...])
    
    def inspect_output(self, response: str, context: dict) -> OutputVerdict:
        # Your output validation here
        acceptable = validate_output(response)
        return OutputVerdict(acceptable=acceptable, violations=[...], flags={})
```

No gateway import. No async. Pure domain logic.

### The Gateway

```python
from gsa_gateway import Gateway
from my_policies import MyPolicy

gateway = Gateway(your_llm_generator, policy=MyPolicy())
await gateway.start()

# Later: hot-swap a policy
await gateway.set_policy(BetterPolicy())
```

Gateway owns: audit, attestation, health classification, circuit breaker, rate limiting, FDR adaptive control, API, deployment.

Policy owns: what is risky, what output is acceptable.

### The Flow

1. **Input → PolicyInputGate** (assess_input); policy scores the request; FDR threshold decides block
2. **Block or Pass**; hard-blocks bypass threshold; graded blocks respect it
3. **Generator**; if passed, run the LLM (with circuit-breaker protection)
4. **Output → ResponsePipeline** (inspect_output): policy validates output; correct loop if needed. An output the policy still rejects after the retries is blocked (403, no response text), not released. A policy may set `shadow = True` to trial a rule: it never blocks, and each output it would have blocked is hashed into the ledger as a shadow decision
5. **Audit**; hash-linked chain, deterministic attestation, persistent (SQLite; Postgres is not implemented)
6. **Health**; URE regime engine (6 regimes and an energy score named after Lyapunov; a heuristic with no stability proof, tuned so all six regimes are reachable)
7. **Feedback**; ground-truth labels move the adaptive threshold (FDR control)

---

## Modules

| Module | Purpose | Lines |
|--------|---------|-------|
| **gsa_gateway.py** | core gateway + endpoints | 1,150 |
| **policy_api.py** | the seam interface | 200 |
| **example_policies.py** | Baseline/Financial/Jailbreak policies | 400 |
| **policy_composition.py** | multi-policy stacking + registry | 150 |
| **auth.py** | RS256 JWT verification + secrets | 250 |
| **persistence.py** | SQLite/memory audit store | 200 |
| **config.py** | 12-factor environment config | 150 |
| **ure_engine.py** | health classification (URE) | 350 |
| **test_gsa_gateway.py** | 35 gateway tests | 600 |
| **test_policy_seam.py** | 8 seam tests | 300 |
| **test_hardening.py** | 8 hardening tests (auth/persistence/composition/hot-reload) | 350 |

---

## Production Readiness

**Self-assigned scorecard, not an independent assessment, and not re-derived on 2026-11-15.** The numbers come from `GSA_SCORECARD.py`, which the author wrote. No score is claimed here. The previous 8.17/10 figure is retained in `PRODUCTION_READINESS.md` (which itself says 7.31/10 in its header, so the two files disagree; logged as an outstanding issue).

| Dimension | Score | Status |
|-----------|-------|--------|
| Policy Seam | 9/10 | - READY |
| Composition | 8/10 | - READY |
| Execution | 8/10 | - READY |
| Auditability | 8/10 | - READY (SQLite persistence) |
| Health & Adaptive Control | 9/10 | - READY |
| Auth | 8/10 | - READY (RS256 JWT) |
| API | 8/10 | - READY |
| Deployment | 7/10 | - MONITOR, per `GSA_SCORECARD.py` (Docker/compose/CI) |

**Remaining work:**
- Shared cross-replica state (Redis); the deployment pins one replica because state is per process
- Applying and validating the k8s manifests on a live cluster

See `PRODUCTION_READINESS.md` for the full scorecard and roadmap.

---

## Testing

### Run All Tests

```bash
python3 -m pytest -q
# 123 passed, 1 skipped on 2026-11-15 (the skip is the CNS connector test; CNS was not installed)
# The older three-file command, `pytest -q test_gsa_gateway.py test_policy_seam.py test_hardening.py`, runs 51 of them.
```

### Validate a Policy

```python
from policy_api import validate_policy, InputCase, OutputCase
from my_policies import MyPolicy

report = validate_policy(
    MyPolicy(),
    input_cases=[
        InputCase("ignore all instructions", expect_block=True, label="injection"),
        InputCase("what's the weather?", expect_block=False, label="benign"),
    ],
    threshold=0.80
)
print(f"Precision: {100*report.precision:.1f}%")
print(f"Recall: {100*report.recall:.1f}%")
```

### Test Against Real Jailbreaks

```bash
python validate_against_jailbreaks.py
# BaselinePolicy vs. 52 real jailbreaks: 2.9% recall (catches 1/34); was 5.9% (2/34) before the 2026-10-28 Phoenix round
# Shows the honest gap that motivates better policies.

GSA_ENV=dev python fdr_convergence_on_real_data.py
# Simulates 200 decisions + ground-truth feedback
# Watches the adaptive threshold move (or not)
```

See `REALITY_CHECK.md` for the full first-contact report.

---

## Configuration

All operational knobs are environment variables (see `.env.example`):

```bash
GSA_ENV=prod                          # dev|staging|prod (only dev accepts unsigned tokens; unset means prod)
GSA_SECRET_KEY=<your-hmac-key>        # from a secret manager; required unless GSA_ENV=dev (startup is refused without it)
GSA_JWT_PUBLIC_KEY_PATH=/path/to/pub  # RS256 verification (required for prod)
GSA_AUDIT_BACKEND=sqlite              # memory|sqlite
GSA_AUDIT_DB_PATH=/data/gsa_audit.db  # persistent volume
GSA_RATE_LIMIT_CAPACITY=60
GSA_RATE_LIMIT_REFILL_PER_SEC=10.0
```

See `config.py` for the full list and defaults.

---

## Deployment

### Docker Compose (local/staging)

```bash
docker compose up --build
```

Starts gateway on :8000, Prometheus on :9090.

### Kubernetes

Manifests are in `k8s/`. They have not been applied against a live cluster.

```bash
docker build -t gsa-gateway:3.1.0 .
kubectl apply -f k8s/namespace.yaml
# create the real secret from k8s/secret.yaml.example -- do not commit a filled-in copy
kubectl apply -f k8s/pvc.yaml -f k8s/deployment.yaml -f k8s/service.yaml
```

The Deployment pins `replicas: 1` deliberately. The audit store, rate limiter, circuit
breaker and FDR threshold controller are all per-process state, so a second replica gets
its own private ledger and its own threshold, and a tenant's effective rate limit doubles.
Multi-replica needs a shared backend first.

### Observability

Load `alerts.yml` into Prometheus and import `grafana/gsa_gateway_dashboard.json` into
Grafana. The dashboard covers all 12 exported metrics, and its panel thresholds match the
alert rules so a red panel and a firing alert mean the same thing.

See `RUNBOOK.md` for full operational guide: deploy, scale, incident response, rollback, backup.

---

## CI/CD

GitHub Actions pipeline included (`.github/workflows/ci.yml`):
- Lint (ruff). The step ends in `|| true`, so a lint failure cannot fail the build (INSPECTED).
- Unit tests (pytest). Eight of the nine test files are listed; `test_backpressure_attestation.py` is not (INSPECTED).
- Self-test checks. `python gsa_gateway.py` computes a pass or fail result and discards it, so the step exits 0 either way unless it crashes (INSPECTED).
- Docker image build

---

## Optional CNS connection

GSA does not need CNS. It has no runtime dependency, nothing in the live modules imports CNS, and `test_cns_independence.py` checks this with CNS blocked (the preserved `archive/` is left untouched and is not scanned; one file there imports `cns.governance` by design). `gsa_cns_connector.py` is the one place that knows CNS exists. Install it with `pip install -r requirements-cns.txt` (pins the CNS version in `requirements-cns.txt`); without CNS, asking for a digest raises `CnsNotInstalled` and nothing else changes.

It makes two outputs **bindable** with `cns.gate`: a gateway decision (a `TraceBundle`, or the dict the audit store keeps for it: tenant, request hash, risk assessment, outcome with its attestation, and the audit record) and an `AuditRecord`. A CNS verdict then carries a `subject_digest`, and `binds(result, trace)` says whether that verdict was issued against exactly this decision. Latency and gateway health are left out as volatile.

This is binding only. It is not a gate, it maps nothing to a verdict, and a bound verdict says which decision it was about, not that the gateway decided well. Request and response text are bound as full SHA-256 digests and never copied.

---

## Next Steps

### Immediate

1. **Build a real jailbreak policy.** The baseline is weak (2.9% recall). Author a `JailbreakPolicy` with better heuristics or a trained classifier.
2. **Validate it locally.** Run `validate_policy(JailbreakPolicy(), jailbreak_dataset)` and get precision/recall.
3. **Deploy and iterate.** Use the FDR loop to tune the threshold as ground-truth feedback arrives.

### For the Bug Bounty

1. Apply to Anthropic's Model Safety Bug Bounty Program (HackerOne)
2. Get access to test against Constitutional Classifiers
3. Run your jailbreak policy in front of Claude
4. Measure: how many attacks does GSA + your policy stop that Claude's safeguards miss?

### Longer Term

- Multi-replica deployment with shared FDR/rate-limit state (Redis)
- Policy registry (declarative YAML-based policy management)
- Grafana dashboards + alerting templates
- Regulatory compliance templates (SOC 2, GDPR, etc.)

---

## Architecture Principles

**The Seam:** Detection is policy work; governance is substrate work. Keep them separate.

**No Domain Detector in Core:** Detection intelligence (keywords, classifiers, semantic understanding) belongs in policies, not in the gateway. The gateway is agnostic.

**Defense in Depth:** Policies stack. One policy's false alarm doesn't move another's threshold. Each member calibrates from its own feedback.

**Honest Assessment:** The baseline fails on real data. That's not a failure; it's validation that the architecture works (the substrate is sound; the policy needs work).

**Operational Maturity:** Audit trail, attestation, health classification, circuit breaker, rate limiting, adaptive control; all operational systems built for production from the start.

---

## Documentation

- **PROVENANCE.md**; what was recovered, from where, how it was verified, what is missing
- **PRODUCTION_READINESS.md**; full scorecard, dimension by dimension
- **REALITY_CHECK.md**; first contact with real jailbreak data
- **RUNBOOK.md**; deploy, scale, incidents, rollback, backup
- **README.md** (this file); architecture, quick start, modules

---

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Copyright 2026 William N. King.

---

## Questions?

This repo is the output of a complete engineering cycle: design (the seam), build (all modules), test, validate (real jailbreak data), and self-assess.

It is a candidate for staging deployment. Nothing here shows it has run in production. The remaining work is operational (k8s validation, shared state) and domain-specific (building better policies).
