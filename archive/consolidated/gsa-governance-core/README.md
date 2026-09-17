# GSA Governance Operating Core (Enterprise)

**Version:** 5.0.0
**Architecture Family:** GSA / Citadel / AEGIS Unified Governance Runtime
**Classification:** Enterprise Deterministic Governance Control Plane

---

## Overview

Unified Governance Operating Core that converts untrusted execution requests into verified, traceable, governed execution artifacts.

### Implemented Layers

| Layer | Status |
|-------|--------|
| Data Governance | ✓ |
| Integrity Validation | ✓ |
| Provenance Tracking | ✓ |
| Zero Trust Execution | ✓ |
| Identity Governance | ✓ |
| Policy Enforcement | ✓ |
| Human Approval Workflow | ✓ |
| Cryptographic Sealing | ✓ |
| Immutable Audit Ledger | ✓ |
| Universal Adapter Boundary | ✓ |
| Kernel Registry | ✓ |
| Module Attestation | ✓ |
| Capability Discovery | ✓ |
| Runtime Health Monitoring | ✓ |
| Circuit Breaker Protection | ✓ |
| Rate Limiting | ✓ |
| Adaptive Threshold Control | ✓ |
| Resilience Plane | ✓ |
| Unified Execution Orchestration | ✓ |
| Diagnostics & Self-Testing | ✓ |
| Production Entrypoint | ✓ |

**Architectural Principle:**
> Governance is not a feature.
> Governance is the execution substrate.

This is the fullest version of this module that was ever built: 21 of 21
planned layers present and exercised by the self-test, at 4,985 lines, with
zero external dependencies. See [PROVENANCE.md](PROVENANCE.md) for exactly
where "fullest" was measured from and what was cut to get there.

---

## Status — read before relying on this

This is a **self-contained reference runtime**, not a production governance
system. It was never deployed and never sat on any live request path. The
repository it was extracted from (`GSA-815`, an IVR/call-center governance
application) ran its actual production governance through a separate,
different implementation — a persistent Postgres ledger with a global hash
chain, DB-level immutability triggers, a witness ("twin"), and keyed HMAC
attestation — in the `sentinel_os` kernel it depends on. This module was kept
alongside that real system purely as a design reference and a runnable demo,
never wired into it.

A `✓` in the table above means "a layer object exists and runs in the
self-test," not "production-hardened." Specifically, in this file:

- **`GovernanceLedger`** ("Immutable Audit Ledger") is an in-memory `dict`
  (`self.chain = {}`). It does not persist — every entry is gone on process
  exit — and each entry is an independent per-`execution_id` SHA-256 digest,
  not a global append-only chain linking one execution to the next. Nothing
  makes it immutable.
- **`AttestationService.attest()`** ("Module Attestation") hashes a module's
  name/version/description and records `verified=True` unconditionally;
  `verify()` returns that stored flag. It attests that a record was created,
  not that anything was independently checked.
- **`CryptographicSealEngine.seal()`** ("Cryptographic Sealing") wraps a
  digest in a dataclass with a timestamp; it does not sign or seal.

`test_harness.py` demonstrates nine further gaps directly (identity accepts
any token, Citadel checks are substring-only, human approval always
auto-approves after 10ms, the output gate and sanitizer both leak sensitive
strings, nested policy keys are ignored, the ledger silently overwrites same-
ID entries, the circuit breaker is never consulted, and provenance is empty
on the success path). Running it prints each flaw and exits 1 on purpose —
that is the expected, correct result, not a broken test suite.

These are fine properties for a deterministic reference/simulation runtime
built to demonstrate an execution *shape*. They are not an audit trail. If
you need one, this is the wrong file to start from.

---

## Requirements

- Python 3.10+ (uses `dataclasses.slots`, `from __future__ import annotations`)
- No external dependencies — pure standard library (`asyncio`, `hashlib`, `json`, `uuid`, etc.)

---

## Quick Start

```bash
python GSA_Governance_Operating_Core_Enterprise.py
```

This runs:

1. Runtime diagnostics
2. Governance self-test
3. Short simulation (5 executions)
4. One full production governed execution

Expected output includes:

```
GSA GOVERNANCE CORE ONLINE
```

followed by diagnostic results, self-test pass, simulation report, and a sealed `UnifiedExecutionResult`.

```bash
python test_harness.py
```

Runs the adversarial harness above. Expected: 9 flaws printed, exit code 1,
`happy_path` still passing.

---

## Core Execution Flow

```
Request
  │
  ▼
Identity Verification
  │
  ▼
Envelope Creation
  │
  ▼
Data Governance (sanitize + hash)
  │
  ▼
Policy Evaluation
  │
  ▼
Integrity Validation (Citadel Diamond)
  │
  ▼
Adapter / Router
  │
  ▼
Execution
  │
  ▼
Output Governance Gate
  │
  ▼
Cryptographic Seal
  │
  ▼
Immutable Ledger Commit
```

---

## Project Layout

```
gsa-governance-core/
├── GSA_Governance_Operating_Core_Enterprise.py   # the full reference runtime
├── test_harness.py                               # standalone adversarial harness (not a pytest file)
├── README.md
├── PROVENANCE.md
└── LICENSE
```

---

## License

Apache-2.0 (`LICENSE`), matching the sibling repos this was recovered from
(`GSA-815`, `GSA-Master-Kernel`). The README that shipped alongside this
module inside `GSA-815` carried a "Proprietary / Internal use" line instead;
see [PROVENANCE.md](PROVENANCE.md) for why this repository uses Apache-2.0
going forward.
