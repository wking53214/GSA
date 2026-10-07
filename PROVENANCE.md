# Provenance

This repository is a **reconstruction**. No original GSA working tree survived. Everything
here was recovered from archived development transcripts and re-verified by execution.

This file records exactly what was recovered, how, from where, and what is still missing.

---

## What GSA is

A universal LLM-governance control plane. It sits in front of any model and enforces
pluggable policies without modifying the model. Its organizing idea is the **policy seam**:
detection ("what is risky") is policy work; governance (audit, attestation, health,
rate limiting, circuit breaking, adaptive thresholds) is substrate work. The two never mix.

The acronym expands differently across sources, which is itself a lineage signal:

| Expansion | Source | Date |
|---|---|---|
| Governance Systems Architecture | Gemini extraction entity registry (`ENT-GOVERNANCE_OS_FULL`) | 2026-04-11 |
| Governance-State Architecture | CoPilot transcript, GSA/DIT 7-layer stack | 2026-05-16 |
| Governance Substrate Architecture | Claude build sessions, GSA-815 README | 2026-07-31 |

The first two describe the conceptual framework (CITADEL / DIT lineage). The third
describes the working software in this repository.

---

## Peak state selected

**v3.1.0 — the Secure Inference Gateway platform**, as it stood at the close of the
2026-07-31 session: 18 Python modules, 51 passing tests, a self-scored 8.17/10 production
readiness assessment, and a full container/CI/observability deployment surface.

This was chosen over the other candidate — `GSA.py` v5.0.0, the 4,985-line monolith that was
the literal content of the GSA repository as of 2026-07-22 (commit `54f2479`, "Deploy
enterprise deterministic governance control plane"). That file is larger and claims more
layers, but a contemporaneous code review in the archive found its load-bearing controls
were stubs: `IdentityFabric.authenticate()` accepted any non-empty string as a valid
credential, `HumanApprovalWorkflow.request()` returned `approved=True` unconditionally, the
"immutable ledger" was a process-local dict with no cross-record chain, and `main()` crashed
on a missing import. It had no tests.

Peak *capacity* is the version whose controls actually hold under test, not the version with
the most class names. The v5.0.0 monolith is preserved in `archive/` for lineage, not as the
runtime.

---

## Sources

| # | Source | What it supplied |
|---|---|---|
| 1 | `Claude_History` conversation `0d8f9021-a6de-438a-b6cc-0c92bdd322d6` ("GSA"), 110 messages, 2026-06-19 → 2026-07-31 | **Primary.** Every module, test, doc, and deployment file in the repository root |
| 2 | `Claude_History` conversation `10d95ca3-6e5a-47a8-bd3a-cc85cd3f6c99` ("Pull wking53214/GSA"), 2026-07-22 | Recorded state of the original repo and the review of `GSA.py` v5.0.0 |
| 3 | `CoPilot_History/transcripts/GSA_and_DIT_Architecture_Analysis.md`, 2026-05-16 | GSA/DIT conceptual framework, 7-layer stack, escalation ladder |
| 4 | `Gemini_Extraction` entity registry and `investigations/GSA/` | Earliest observed GSA reference (2026-04-11), CITADEL/DIT lineage |
| 5 | `wking53214/GSA-815` @ `02a977b` | Preserved copy of `GSA_Governance_Operating_Core_Enterprise.py` v5.0.0 and its harness |

---

## Recovery method

The Claude export preserves full tool-call inputs, so file writes were not summarized away —
they were replayed.

1. Walked conversation #1 in message order, applying every recorded file operation to an
   in-memory filesystem: **22 `create_file` writes, 95 `str_replace` edits, 25 shell heredoc
   writes**, with shell working directory tracked so relative paths resolved correctly.
2. Exact string matching first; where an edit's anchor text had drifted, fell back to
   matching on the first and last non-blank lines of the target block with an 0.80
   similarity floor.
3. **91 of 95 edits applied, and all 4 misses were verified to be no-ops.** Each was
   superseded by a later whole-file rewrite that had already produced the intended end
   state: the `HealthReport` removal, the `ATTACKED` regime trigger condition, the URE
   calibration rationale in `GSA_SCORECARD.py` (already at 9/10 with the calibrated text),
   and the error-handling rationale in the earlier scorecard (whose dimension set was
   replaced wholesale). **No edit is outstanding.** An earlier version of this file claimed
   two cosmetic edits were still missing; that was wrong, and checking each anchor against
   the reconstructed files is what disproved it.
4. Backup-copy (`cp`) operations were deliberately **not** replayed. Replaying them restored
   stale snapshots over newer state and regressed the reconstruction from 4 failures to 15.

---

## Verification

Run in a clean Python 3.11 virtualenv against `requirements.txt`, not copied from the archive:

| Check | Archived claim | Reproduced |
|---|---|---|
| Test suite | 51 passing (35 gateway + 8 seam + 8 hardening) | **51 passed** |
| Module compilation | — | 18/18 compile clean |
| Gateway self-test + demo | ALL PASS | **ALL PASS**, ledger `chain_valid=True` |
| URE calibration sweep | idle→NOMINAL/NEUTRAL, all 6 regimes reachable, no UNKNOWN | **matches** |
| Load test | 2,800–3,500 req/s, p99 ~30ms, 0 errors | **2,872 req/s, p99 39ms, 0 errors** |
| Production scorecard | 8.17/10 | **8.17/10** |
| Jailbreak conformance | BaselinePolicy 5.9% recall, 100% precision | **6% recall, 100% precision** |

That last row is an honest recorded weakness, not a reconstruction defect. The shipped
`BaselinePolicy` is a keyword matcher and catches 2 of 34 real jailbreaks. The archive's
`REALITY_CHECK.md` documents this deliberately: it demonstrates that the substrate measures
policy quality correctly, and that the gap is policy work, not architecture work.

---

## Known gaps

- **No LICENSE in the archived source.** Resolved 2026-10-07: licensed under Apache-2.0 (see `LICENSE`).
- **`archive/gsa_core_framework_v85.py` is partial** (93 lines). The full "GSA Core Framework
  v8.5" text was pasted into the session but only the excerpt written to disk survives as code.
- **No Helm chart or Terraform.** `k8s/` ships plain YAML manifests, added after the
  reconstruction (see "Added after reconstruction" below). They have not been applied
  against a live cluster.
- **Multi-replica is not supported.** The audit store, rate limiter, circuit breaker and FDR
  threshold controller are all per-process state, so the k8s manifests pin `replicas: 1` on
  purpose. Scaling out requires a shared backend, which the scorecard lists as the main
  remaining work toward 8.5.
- **Original commit history is unrecoverable.** The archive records two commits in the
  build session's staging directory but not their contents as distinct trees.

---

## Archive directory

`archive/` holds lineage artifacts. Nothing in the runtime imports them.

| File | What it is |
|---|---|
| `GSA_Governance_Operating_Core_Enterprise.py` | v5.0.0 monolith, 4,891 lines — the literal content of the GSA repo as of 2026-07-22. Reviewed as scaffold; controls are stubs. Kept for lineage |
| `GSA_Governance_Operating_Core_test_harness.py` | Its demo harness |
| `gsa_kernel_v3_initial.py` | First working kernel from the 2026-06-19 session |
| `gsa_kernel_v3_hardened.py` | Same kernel after the hardening pass, with `# FIX:` markers inline |
| `gsa_core_framework_v85.py` | Excerpt of the v8.5 framework (CITADEL/DIT severity ladder, persistence layer) |
| `PRODUCTION_READINESS_SCORECARD_7.19.py` | Earlier state of the live scorecard, same nine dimensions at 7.19/10 |


---

## Added after reconstruction

Everything above this section came out of the archives. The following did not, and is
marked separately so the reconstruction stays auditable:

| Path | What it is |
|---|---|
| `k8s/` | Deployment, Service, PVC, Namespace and a Secret template for the gateway. Structure and security posture (non-root pod context, dropped capabilities, read-only root filesystem, seccomp) follow the manifests in the descendant `GSA-815` repo; the workload, ports, probes and environment are GSA's own, taken from `Dockerfile` and `config.py`. Valid YAML, never applied to a cluster |
| `grafana/gsa_gateway_dashboard.json` | 16 panels over all 12 Prometheus metrics the gateway actually exports. Panel thresholds match `alerts.yml`. Valid JSON, never loaded into a live Grafana |

Two scorecard edits accompany them, both narrowing claims rather than raising scores:
the `Deployment & Operations` and `Operational Health` gap lists now say these artifacts
exist but are unvalidated. **The 8.17/10 total is unchanged.** Shipping a manifest is not
the same as proving it runs, and the score should not move until it does.

`PRODUCTION_READINESS_SCORECARD.py` was moved to `archive/PRODUCTION_READINESS_SCORECARD_7.19.py`.
It scored the identical nine dimensions at 7.19/10 and is an earlier state of the same
document as `GSA_SCORECARD.py`, not a competing assessment. Two disagreeing scorecards in
the repository root was a reconstruction artifact, not a historical fact.

## Licensing (resolved 2026-10-07)

> **Resolved.** The owner licensed GSA under the Apache License 2.0 (`LICENSE`, `NOTICE`).
> The note below is kept as it was written.

No LICENSE file existed in the archived source, and none has been added here. Without one,
the default applies: all rights reserved, and nobody may use, copy, or modify this code.
That may be exactly what you want for a private repository. If GSA is ever shared, shown to
a customer, or submitted to a bug-bounty program, it needs an explicit license, and that is
an owner's decision rather than something a reconstruction should assume.
