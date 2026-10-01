# Provenance

## What this is

This repository holds one file's history: `GSA_Governance_Operating_Core_Enterprise.py`,
a self-contained "Unified Governance Operating Core" reference runtime, at the
fullest, most feature-complete state it ever reached across its life inside
another repository. It was recreated here, standalone, because `GSA-GOVERNANCE-CORE`
had existed only as a concept — a name for this module's role — never as its
own repository, until now.

## Lineage

| Stage | Where | What happened |
|---|---|---|
| Design | A 10-turn Google Gemini conversation, *"GSA (Governance Systems Architecture) Master Kernel"* | The conversation produced 15 code blocks (`artifact_1.py`–`artifact_15.py`). Only 4 of the 15 execute as extracted; the rest are single-line flattened pastes or fragments with no entry point. |
| First landing | [`wking53214/GSA-815`](https://github.com/wking53214/GSA-815), bulk-imported during an August 2026 run of `Integrate <X> module into GSA-815` commits | The transcript was flattened into several root-level files, including four separate copies of the governance core (`GSA.py`, `GSA/GSA.py`, a root `GSA_Governance_Operating_Core_Enterprise.py`, and `gsa-governance-core/GSA_Governance_Operating_Core_Enterprise.py`). The two full copies differed by 7 trivial lines. |
| Consolidation | GSA-815, commit `142e997` ("Dead-weight sweep + governance-core consolidation", PR #7, 2026-09-03) | Three of the four copies were deleted as zero-importer duplicates. `gsa-governance-core/` — the one already carrying an honest README and a `test_harness.py` — was kept as the single canonical copy. Its 178 KB source transcript and the other transcript-derived artifacts were split into their own archived repository, [`wking53214/GSA-Master-Kernel`](https://github.com/wking53214/GSA-Master-Kernel). |
| Housekeeping | GSA-815, commits `cea0b25` (#8), `66658d4` (#9, first CI + `ruff` hard gate) | `ruff` surfaced 9 findings in `gsa-governance-core/`, fixed here: 2 unused imports, 1 unused local, `test_harness.py` formatting. File went from 4,987 to 4,985 lines. Still fully self-contained. |
| Doc fix | GSA-815, commit `44ee595` (#10) | `gsa-governance-core/README.md`'s Project Layout table corrected. **This is the commit this repository's `GSA_Governance_Operating_Core_Enterprise.py`, `test_harness.py`, and (adapted) README are taken from** — the last point at which the module was both fully self-contained and had its cleanest, ruff-passing form. |
| Dependency extraction | GSA-815, commit `5c5994a` ("import the fourteen contracts from cns instead of redefining them") | The module's 14 governance contract classes (`PolicyViolation` and 13 others) were byte-identical to ones already defined in a separate, private package (`cns`, pinned in GSA-815's `requirements.txt`). That commit replaced 124 lines of local definitions with a 30-line import, so the shared names would be the same objects (`isinstance` holds across the boundary) rather than merely identical shapes. Functionally a strict improvement inside GSA-815 — but it makes the file depend on a private package this repository does not have access to. **This repository intentionally uses the pre-`5c5994a` version instead**, so it stays runnable standalone with zero external dependencies, as `python GSA_Governance_Operating_Core_Enterprise.py` and `python test_harness.py` both verify. |

## Why "peak capacity" means this specific commit

Three candidate points were considered:

1. **The original Gemini transcript artifacts** (`GSA-Master-Kernel`) — richer in
   ambition (15 artifacts, multiple named variants: `GovernanceSystemsArchitectureMasterKernel`,
   `GSA_Universal_Cryptographic_Interlock_Engine`, `DeterministicASTGraphExtractor`),
   but per `GSA-Master-Kernel/PROVENANCE.md`, 11 of the 15 never ran at all —
   not a "peak," a design sketch.
2. **The four duplicate copies inside GSA-815, pre-consolidation** — more
   files, zero additional capability (the copies differed by at most 7 trivial
   lines). More copies is not more capacity.
3. **`gsa-governance-core/` at commit `44ee595`** — one file, 4,985 lines, all
   21 layers in the status table present and exercised by `test_harness.py`,
   zero external dependencies, `ruff`-clean. This is what's in this repository.

The later `5c5994a` commit is real progress for GSA-815 (shared contract
identity with `cns`), but it is progress achieved by *removing* code from
this file and pointing it at something outside this file's own boundary.
Since this repository's purpose is to preserve the module as its own
complete, standalone thing, the version before that extraction is the
correct "peak."

## What was verified before publishing

- `python GSA_Governance_Operating_Core_Enterprise.py` — exit 0. Runtime
  diagnostics all healthy, self-test passed, 5/5 simulation executions
  succeeded, one full governed execution reached `RELEASED`.
- `python test_harness.py` — exit 1, as documented: 9 of 10 checks fail on
  purpose to demonstrate known flaws (identity accepts any token, Citadel
  checks are substring-only, human approval auto-approves, the output gate
  and sanitizer both leak sensitive strings, nested policy keys are ignored,
  the ledger silently overwrites same-ID entries, the circuit breaker is
  never consulted, provenance is empty on success); `happy_path` passes.

## What this repository is not

It is not a revival of `GSA-815`'s production governance path (that path is
`sentinel_os`'s Postgres-backed ledger — see `GSA-815/DEPENDENCIES.md`), and
it is not a merge of the four historical duplicate copies or the 15
Gemini-transcript artifacts. Those remain where they are:

- Production governance kernel: [`wking53214/sentinel_os`](https://github.com/wking53214/sentinel_os)
- Domain application built on it: [`wking53214/GSA-815`](https://github.com/wking53214/GSA-815)
- Original design transcript + all 15 extracted artifacts: [`wking53214/GSA-Master-Kernel`](https://github.com/wking53214/GSA-Master-Kernel)

## License

Proprietary, all rights reserved (`LICENSE`). Inside GSA-815,
`gsa-governance-core/README.md` closed with "License: Proprietary / Internal use
unless otherwise specified by the architecture owner", which described this
module's intent without a matching license file. This repository now carries
an all-rights-reserved `LICENSE`, which replaced an Apache-2.0 text that was
present earlier.
