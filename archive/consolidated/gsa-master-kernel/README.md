# GSA-Master-Kernel

An **archived Google Gemini transcript** — a 10-turn conversation headed *"GSA
(Governance Systems Architecture) Master Kernel"* — together with its
provenance record and the 15 code blocks extracted from it.

This is not a system. It is a preserved design conversation. The transcript's
own naming is inconsistent: it says both *"Governance Systems Architecture"*
and *"Governance State Architecture / Decalogue Stack"*, and the individual
artifacts carry three different program names
(`GovernanceSystemsArchitectureMasterKernel`,
`GSA_Universal_Cryptographic_Interlock_Engine`,
`DeterministicASTGraphExtractor`).

- **`TRANSCRIPT.md`** — the complete conversation, verbatim.
- **`PROVENANCE.md`** — full record: source, what each turn contains, which of
  the 15 artifacts run (4 of 15 execute; the rest are single-line flattened
  raw pastes or entry-point-less fragments), what was stripped during
  extraction, line/char counts.
- **`artifact_1.py` … `artifact_15.py`** — the extracted code blocks, numbered
  in transcript order (none names its own file). Copied byte-for-byte from the
  source; **not** cleaned up or made to run.

It was previously the `GSA-2/` subdirectory of
[wking53214/GSA-815](https://github.com/wking53214/GSA-815); split out and
archived 2026-09-03 so a live application repo isn't carrying a 178 KB design
transcript. Some of GSA-815's now-removed root files
(`gsa-master-kernel-base-flattened.py`, the interlock wrappers) and its
`gsa-governance-core/` reference runtime descend from this conversation.

## License

Proprietary, all rights reserved (`LICENSE`). The transcript content is a preserved AI conversation;
the license covers this repository's arrangement of it.
