# Consolidated GSA repositories

Contents of three separate GSA repositories, merged into this one as the
canonical home. Nothing was discarded except a single file proven
byte-identical to one already here.

Source repositories are unchanged by this commit. Archive or delete them
only after reviewing this document.

## Scope

| Repository | Files | Disposition |
| --- | ---: | --- |
| `GSA` (this repo) | 51 | **Canonical.** Has CI, Dockerfile, k8s manifests, tests. |
| `GSA-Master-Kernel` | 20 | Merged into `gsa-master-kernel/`. |
| `GSA-GOVERNANCE-CORE` | 6 | Merged into `gsa-governance-core/`. Superseded, see below. |
| `GSA-2` | 0 | **Empty. No commits at all.** Nothing to merge. |
| `GSA-GATEWAY1` | 0 | **Empty. No commits at all.** Nothing to merge. |
| `GSA-815` | - | Excluded from this consolidation by request. |

`GSA-GATEWAY` does not exist. Only `GSA-GATEWAY1` does, and it is empty.

Emptiness was confirmed with `git ls-remote`, which returns zero refs for
those repositories. That means no commits on any branch, not merely an empty
working tree.

## Duplication evidence

Two files were found to be duplicates of content already in this repository.
Both were located by structural fingerprint, not by filename.

### Byte-identical (excluded from the copy)

`GSA-GOVERNANCE-CORE/test_harness.py` is byte-for-byte identical to
`archive/GSA_Governance_Operating_Core_test_harness.py`, already present here.
It was not copied. Its hash is recorded in `manifest.json`.

### Structurally identical, textually different (copied and flagged)

`GSA-Master-Kernel/artifact_11.py` defines exactly the same symbols and the
same relationships between them as `archive/gsa_kernel_v3_initial.py`. The
bytes differ, so it was copied rather than dropped. Comments, formatting or
docstrings differ; the code shape does not.

This is the case plain diffing misses and filename comparison cannot see:
the two files have unrelated names.

### Also worth knowing: a duplicate already inside this repo

`GSA_SCORECARD.py` and `archive/PRODUCTION_READINESS_SCORECARD_7.19.py` are
structurally identical to each other. Both predate this commit and neither was
touched. Flagged for a separate decision.

## Why GSA-GOVERNANCE-CORE is superseded

`GSA-GOVERNANCE-CORE/GSA_Governance_Operating_Core_Enterprise.py` (4,985 lines)
defines fourteen governance contracts inline.

`archive/GSA_Governance_Operating_Core_Enterprise.py` in this repo (4,891
lines) is the later refactor: it imports those same fourteen contracts from
the private `cns.governance` package and re-exports them, keeping existing
imports working.

All fourteen were verified present as class definitions in
`wking53214/CNS` at `cns/governance.py`:

    AuthorizationError   ExecutionDomain   GovernanceError   IdentityContext
    IntegrityError       IntentCategory    KernelComponent   KernelMetadata
    PolicyViolation      QueueType         RoutingDecision   RoutingError
    TrustLevel           ValidationError

So the content of GSA-GOVERNANCE-CORE survives in two places: the engines,
fabrics, gates and ledgers in this repo's `archive/` copy, and the contracts
in CNS. Its copy is preserved here regardless, because superseded is not the
same as identical.

**This creates a real dependency.** `archive/GSA_Governance_Operating_Core_Enterprise.py`
will not import without `cns.governance` on the path. That was already true
before this commit.

## Condition of the GSA-Master-Kernel artifacts

`artifact_1` through `artifact_15` are not ordinary source files. They are
extracted chat artifacts, and six of them have had every newline stripped,
leaving the entire file on a single line:

| File | Bytes | Newlines | State |
| --- | ---: | ---: | --- |
| `artifact_1.py` | 8,857 | 0 | newline-stripped |
| `artifact_3.py` | 5,222 | 0 | newline-stripped |
| `artifact_5.py` | 806 | 0 | newline-stripped |
| `artifact_7.py` | 117 | 0 | newline-stripped |
| `artifact_9.py` | 5,242 | 0 | newline-stripped |
| `artifact_14.py` | 5,376 | 0 | newline-stripped |

Python is whitespace-significant, so none of these six parses. They are
preserved exactly as found, because the damage is itself a fact about the
corpus and re-indenting them would be a guess about original structure.

`artifact_1.py` additionally holds several distinct components concatenated
behind `SYSTEM ... Component: ...` separators, so it is not one module even
once repaired.

The other nine parse cleanly.

### Recovered versions

`GSA-Master-Kernel` later gained repairs for five of those six, merged there
from `claude/recovered-originals`. They are carried here as `*.recovered.py`
**alongside the untouched originals**, so the damage remains inspectable and
the repair is available:

| File | Lines | Parses | Symbols recovered |
| --- | ---: | :---: | --- |
| `artifact_14.recovered.py` | 214 | yes | `GraphExtractor`, `Node`, `Edge`, `Graph`, `extract_graph` |
| `artifact_9.recovered.py` | 220 | yes | `DeterministicPolicyRuntime`, `PolicyResult`, `Telemetry`, `ExecutionResult` |
| `artifact_5.recovered.py` | 30 | yes | `evaluate_environment` |
| `artifact_3.recovered.py` | 189 | no | - |
| `artifact_1.recovered.py` | 428 | no | - |

Three of five are restored to working Python, verified by parsing each and
extracting its symbol table. The two that still fail are the hardest cases:
`artifact_1` holds several components concatenated behind `SYSTEM ...
Component:` separators, so it is not one module even once re-indented.

`artifact_7.py` has no recovered counterpart. At 117 bytes it is a bare list
of names, with nothing to reconstruct.

`manifest.json` records the source HEAD this content came from, and the
previous HEAD it superseded, under `previous_source_head`.

## Verifying this consolidation

`manifest.json` records every source file with its SHA-256 and the source
repository's HEAD commit, so the copy can be checked against the originals
before anything is archived.

Structural comparison was produced with the extractor in
`wking53214/AST`. A structural fingerprint is the sorted set of symbol
names plus the sorted set of (source, target, type) edges, hashed. Two files
with the same fingerprint define the same things and call them in the same
pattern, whatever their text.
