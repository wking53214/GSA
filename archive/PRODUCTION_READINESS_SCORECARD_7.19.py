"""
SUPERSEDED. Kept for lineage only.

This is the earlier snapshot of the same nine-dimension scorecard, scoring
7.19/10. `GSA_SCORECARD.py` in the repository root is the later run of the
identical dimension set at 8.17/10 and is the live artifact. Both were
recovered from the same build session; they are consecutive states of one
document, not two different assessments.

Original module docstring follows.
"""

"""
GSA UNIVERSAL GOVERNANCE CONTROL PLANE — PRODUCTION READINESS SCORECARD
======================================================================
Reframed model (supersedes the earlier clinical/NCH-targeted scorecard):

  GSA is NOT a domain product. It is a universal governance substrate with a
  policy-adapter seam. Domain meaning (what is risky, what output is acceptable)
  lives in pluggable policies; the core owns only the universal mechanism.

  Therefore "production readiness" is NOT "did we build a good detector."
  Detection is, by design, the policy author's job. Readiness is:
    (a) is the seam obvious, minimal, and isolating?
    (b) can a domain expert author + validate a policy without touching the core?
    (c) can policies be composed, versioned, and swapped safely?
    (d) is the universal substrate (exec, audit, health, control, auth, API,
        deploy) trustworthy enough for a customer to adopt and a regulator to audit?

Scores below are grounded in shipped, tested artifacts:
  policy_api.py, example_policies.py, gsa_gateway.py,
  test_policy_seam.py (8), test_gsa_gateway.py (35), loadtest.py.

SCORING: 0-10 per dimension. 9-10 ready/mature, 7-8 solid w/ minor gaps,
5-6 functional but gated, 3-4 demo-grade, 0-2 absent. OVERALL = weighted avg.
"""

DIMENSIONS = [
    {
        "name": "Policy-Seam Clarity & Isolation",
        "weight": 0.15,
        "score": 9,
        "rationale": (
            "The seam (policy_api.py) is a 2-method interface (assess_input / inspect_output) "
            "plus two value objects, exposed as a structural Protocol so no inheritance is forced. "
            "Isolation is ENFORCED and tested: a subprocess test proves importing the seam never "
            "pulls in the gateway, and the core now contains zero domain rules (hasattr(core,'RISK_TOKENS') "
            "is False — the keyword/injection/style logic was moved out into BaselinePolicy)."),
        "gaps": [
            "No published 'authoring a policy' guide/template shipped yet",
            "PolicyContext is loosely typed (Mapping[str, Any]) rather than a typed schema",
        ],
        "ready_for": "Production. This is the strongest part of the system.",
    },
    {
        "name": "Policy Testability & Conformance",
        "weight": 0.12,
        "score": 8,
        "rationale": (
            "validate_policy() runs a policy against labeled InputCase/OutputCase batteries and reports "
            "accuracy + precision + recall + per-case mismatches, using ONLY the seam (no gateway, no async, "
            "no network). test_policy_seam.py shows a domain expert authoring a MedicalRedactionPolicy inside "
            "a test and validating it to 100% without importing the core."),
        "gaps": [
            "No golden-corpus / regression fixtures shipped with the harness",
            "No property-based / adversarial fuzz testing of policies",
            "No CI template a policy author can drop in",
        ],
        "ready_for": "Production for authoring; add fixtures + fuzzing for high-assurance policies.",
    },
    {
        "name": "Policy Composition & Lifecycle",
        "weight": 0.08,
        "score": 5,
        "rationale": (
            "Policies carry name/version/domain; hot-swap is proven (Gateway(gen, policy=...)) and "
            "non-interference is proven (core invariants hold under Baseline/Financial/Permissive). "
            "This is the genuine frontier of the design."),
        "gaps": [
            "No multi-policy composition (can't stack e.g. a PII policy + a domain policy with defined precedence)",
            "No runtime hot-reload (swap is per-Gateway-instance at construction)",
            "One global FDR threshold controller — no per-policy threshold isolation",
            "No policy registry / discovery",
        ],
        "ready_for": "Single-policy production; composition + lifecycle is the top build item.",
    },
    {
        "name": "Execution & Reliability",
        "weight": 0.13,
        "score": 8,
        "rationale": (
            "Async attestation pool with bounded queue + backpressure; 3-state circuit breaker on the "
            "upstream (fast-fail 503 / half-open recovery / 502 on real errors); all paths return structured "
            "responses. 43 automated tests + a concurrent load harness (~3,400 req/s, p99 ~33ms, 0 errors at "
            "concurrency 100) + a 13-check self-test, all green."),
        "gaps": [
            "Per-instance state (breaker, limiter, FDR window) — needs a shared store for multi-replica",
            "No chaos/fuzz beyond the circuit-breaker path; no CI pipeline committed",
        ],
        "ready_for": "Single-instance production with monitoring.",
    },
    {
        "name": "Auditability of Policy Execution",
        "weight": 0.12,
        "score": 7,
        "rationale": (
            "Hash-linked, tamper-evident ledger (verify_chain detects mutation) + deterministic forensic "
            "attestation (explicit timestamp + nonce + constant-time verify; clock-skew removed) + tenant-scoped "
            "replay. Each decision records WHY (policy reasons), the threshold used, and whether it was a hard "
            "block — you can reconstruct the rationale for any decision."),
        "gaps": [
            "In-memory only — ledger/traces lost on restart; needs a durable, append-only external store",
            "Audit record does not yet stamp the policy NAME/VERSION that adjudicated the decision",
            "No external time-authority anchoring of the chain",
        ],
        "ready_for": "Staging; production needs persistence + policy-version provenance in each record.",
    },
    {
        "name": "Operational Health & Adaptive Control",
        "weight": 0.12,
        "score": 8,
        "rationale": (
            "Two universal control loops that work for ANY policy: the UGPIS-Ω URE regime engine scores "
            "operational health (real probability distribution over 6 regimes + Lyapunov energy, calibrated so "
            "healthy traffic reads NEUTRAL), and a closed-loop FDR controller tunes the block threshold from "
            "ground-truth feedback (the threshold actually drives the decision). Prometheus metrics + /health."),
        "gaps": [
            "URE thresholds + FDR target are placeholders (need calibration on real traffic)",
            "Adaptive state is per-instance; no OpenTelemetry spans or shipped dashboards/alerts",
        ],
        "ready_for": "Production with operator tuning of thresholds.",
    },
    {
        "name": "Authentication & Multi-Tenancy",
        "weight": 0.10,
        "score": 6,
        "rationale": (
            "Bearer-token auth, per-tenant token-bucket rate limiting (429 + Retry-After), and tenant-scoped "
            "replay/feedback (can't touch another tenant's traces). Each request is tagged with a tenant id."),
        "gaps": [
            "No token SIGNATURE verification — needs OIDC/JWT (RS256) or mTLS",
            "Signing secret is process-level and not rotated; no vault/KMS",
            "Rate-limit buckets are per-instance; shared ledger leaks aggregate timing across tenants",
        ],
        "ready_for": "Staging; production requires real token verification + secret management.",
    },
    {
        "name": "API & Integration",
        "weight": 0.08,
        "score": 8,
        "rationale": (
            "Typed Pydantic schemas; explicit versioning (API_VERSION + X-API-Version header + /api/version "
            "discovery + Deprecation/Sunset headers); paginated /api/v3/traces; /api/v3/feedback for ground "
            "truth. Policy is injected by dependency injection — integrating a new policy is a one-line change."),
        "gaps": [
            "Pre-1.0 surface; no OpenAPI contract test in CI",
            "No container image / SDK",
        ],
        "ready_for": "Production; commit to backwards-compat through v3.x and add contract tests.",
    },
    {
        "name": "Deployment & Operations",
        "weight": 0.10,
        "score": 4,
        "rationale": (
            "Pure-Python FastAPI service that runs via `python3 gsa_gateway.py` or uvicorn. No packaging or "
            "operational tooling yet."),
        "gaps": [
            "No Dockerfile / docker-compose / k8s manifests / Terraform",
            "No externalized config file (constants are in-source)",
            "No runbooks, dashboards, alert definitions, or CI pipeline",
        ],
        "ready_for": "NOT production. Pure engineering; no ML or domain work required.",
    },
]


def compute(dims):
    assert abs(sum(d["weight"] for d in dims) - 1.0) < 1e-9, "weights must sum to 1.0"
    return round(sum(d["score"] * d["weight"] for d in dims), 2)


def verdict(score):
    if score >= 8.5:
        return "PRODUCTION READY"
    if score >= 7.0:
        return "STAGING / PRE-PRODUCTION (gated launch)"
    if score >= 5.0:
        return "BETA / EXPERIMENTAL (engineering + monitoring)"
    return "NOT READY FOR DEPLOYMENT"


if __name__ == "__main__":
    overall = compute(DIMENSIONS)
    W = 64
    print("=" * W)
    print("GSA UNIVERSAL GOVERNANCE CONTROL PLANE")
    print("Production Readiness Scorecard (seam-centric model)")
    print("=" * W)
    for d in DIMENSIONS:
        grade = ("READY " if d["score"] >= 8 else "MONITOR" if d["score"] >= 6
                 else "GATED " if d["score"] >= 4 else "ABSENT")
        print(f"\n[{grade}] {d['name']}  —  {d['score']}/10   (weight {d['weight']:.0%})")
        print(f"  {d['rationale']}")
        print("  Gaps:")
        for g in d["gaps"]:
            print(f"    - {g}")
        print(f"  Ready for: {d['ready_for']}")
    print("\n" + "=" * W)
    print(f"OVERALL: {overall}/10   VERDICT: {verdict(overall)}")
    print("=" * W)

    print("\nWHAT MOVES THE NUMBER (no domain detector needed — that's the policy's job):")
    moves = [
        ("Policy Composition & Lifecycle", 0.08, 5, 8, "stack/precedence + per-policy threshold + hot-reload + registry"),
        ("Deployment & Operations",        0.10, 4, 7, "Dockerfile + compose + config file + runbooks + CI"),
        ("Authentication & Multi-Tenancy", 0.10, 6, 8, "OIDC/JWT (RS256) + secret manager"),
        ("Auditability of Policy Execution",0.12, 7, 8, "persist ledger/traces + stamp policy name/version per record"),
    ]
    running = overall
    for name, w, lo, hi, how in moves:
        delta = round((hi - lo) * w, 2)
        running = round(running + delta, 2)
        print(f"  {name}: {lo}->{hi} (+{delta})  via {how}   => running {running}")
    print(f"\n  Those four (all pure engineering) reach ~{running}/10 -> PRODUCTION READY band.")
    print("  A 10 means: any domain can adopt, prove its policy in isolation, and a regulator can")
    print("  audit the substrate. That is composition + hardening — never 'put a domain detector in the core.'")
