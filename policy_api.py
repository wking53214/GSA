"""
policy_api.py — the GSA policy-adapter seam
===========================================
This is the ONLY module a domain expert needs to write and validate a policy.

It deliberately imports nothing from the gateway. The governance core (audit,
attestation, health scoring, circuit breaker, rate limiting, adaptive FDR
threshold, ledger) depends on THIS module; never the other way around. That one-
directional dependency is the seam: a policy author works entirely against
policy_api and never sees — or can break — the core.

A policy answers two questions and nothing else:
  1. assess_input(request)  -> how risky is this request?   (InputVerdict)
  2. inspect_output(response) -> is this generated text acceptable? (OutputVerdict)

What the policy does NOT decide (the core owns these, for every policy):
  * the block threshold and its adaptive tuning (graded scores are compared to a
    threshold the core tunes via false-discovery-rate feedback);
  * audit, attestation, health, rate limiting, retries, persistence.

A policy returns a graded `score` (0..1) for threshold-based blocking, and may
additionally assert `hard_block=True` for absolute, non-negotiable rules (e.g.
"a raw SSN is never allowed") that bypass the adaptive threshold.
"""
from __future__ import annotations

from abc import ABC
from dataclasses import dataclass, field
from typing import Any, List, Mapping, Protocol, runtime_checkable


# ---------------------------------------------------------------------------
# Verdict value objects (what a policy returns)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class InputVerdict:
    """A policy's read on an inbound request.

    score:      graded risk in [0, 1]; the core blocks when score >= its (adaptive)
                threshold. Use this for 'how suspicious' judgments.
    hard_block: absolute block regardless of threshold. Use for bright-line rules.
    reasons:    human-readable justifications (shown in the trace / audit record).
    """
    score: float = 0.0
    hard_block: bool = False
    reasons: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not (0.0 <= self.score <= 1.0):
            raise ValueError(f"InputVerdict.score must be in [0,1], got {self.score}")


@dataclass(frozen=True)
class OutputVerdict:
    """A policy's read on generated output. Measurement only — never a rewrite.

    acceptable: may this output be returned as-is?
    violations: named, blocking problems (drive the correction loop when enforced).
    flags:      structured, non-blocking observations, persisted in the trace.
    """
    acceptable: bool = True
    violations: List[str] = field(default_factory=list)
    flags: Mapping[str, Any] = field(default_factory=dict)


# Standard context keys the core passes in (all optional; policies read what they need):
#   "tenant_id"        -> str
#   "request"          -> str   (original request; available at the output stage too)
#   "input_score"      -> float (the input verdict's score; available at output stage)
PolicyContext = Mapping[str, Any]


# ---------------------------------------------------------------------------
# The interface (structural) + an optional base class (nominal convenience)
# ---------------------------------------------------------------------------
@runtime_checkable
class PolicyAdapter(Protocol):
    """Structural interface. Any object with these attributes/methods is a policy;
    you do not have to subclass anything."""
    name: str
    version: str
    domain: str

    def assess_input(self, request: str, context: PolicyContext) -> InputVerdict: ...
    def inspect_output(self, response: str, context: PolicyContext) -> OutputVerdict: ...


class BasePolicy(ABC):
    """Optional convenience base. Subclass and override only what you need:
    an input-only policy can leave inspect_output at its permissive default, and
    vice-versa."""
    name: str = "unnamed-policy"
    version: str = "0.0.0"
    domain: str = "generic"

    def assess_input(self, request: str, context: PolicyContext) -> InputVerdict:
        return InputVerdict(score=0.0)

    def inspect_output(self, response: str, context: PolicyContext) -> OutputVerdict:
        return OutputVerdict(acceptable=True)


# ---------------------------------------------------------------------------
# Conformance harness — validate a policy with ONLY this module imported.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class InputCase:
    text: str
    expect_block: bool          # should this request be blocked? (hard_block OR score>=threshold)
    label: str = ""


@dataclass(frozen=True)
class OutputCase:
    text: str
    expect_acceptable: bool     # should this output pass?
    label: str = ""


@dataclass
class ConformanceReport:
    policy_name: str
    policy_version: str
    domain: str
    threshold: float
    input_total: int = 0
    input_correct: int = 0
    output_total: int = 0
    output_correct: int = 0
    # confusion counts for the input (block = positive)
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    mismatches: List[str] = field(default_factory=list)

    @property
    def input_accuracy(self) -> float:
        return self.input_correct / self.input_total if self.input_total else 1.0

    @property
    def output_accuracy(self) -> float:
        return self.output_correct / self.output_total if self.output_total else 1.0

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 1.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 1.0

    @property
    def passed(self) -> bool:
        return not self.mismatches

    def summary(self) -> str:
        return (f"[{self.policy_name} v{self.policy_version} | {self.domain}] "
                f"input acc={self.input_accuracy:.0%} (P={self.precision:.0%} R={self.recall:.0%}) "
                f"output acc={self.output_accuracy:.0%} "
                f"-> {'PASS' if self.passed else f'FAIL ({len(self.mismatches)} mismatch)'}")


def _would_block(verdict: InputVerdict, threshold: float) -> bool:
    return verdict.hard_block or verdict.score >= threshold


def validate_policy(policy: PolicyAdapter,
                    input_cases: List[InputCase] | None = None,
                    output_cases: List[OutputCase] | None = None,
                    threshold: float = 0.80,
                    context: PolicyContext | None = None) -> ConformanceReport:
    """Run a policy against labeled cases and report accuracy/precision/recall.

    A domain expert calls this with only policy_api imported — no gateway, no
    network, no async. `threshold` mirrors the core's block threshold so the
    expert validates against the same decision rule the gateway will apply.
    """
    ctx = dict(context or {})
    rep = ConformanceReport(policy_name=getattr(policy, "name", "?"),
                            policy_version=getattr(policy, "version", "?"),
                            domain=getattr(policy, "domain", "?"),
                            threshold=threshold)

    for c in (input_cases or []):
        v = policy.assess_input(c.text, ctx)
        blocked = _would_block(v, threshold)
        rep.input_total += 1
        if blocked == c.expect_block:
            rep.input_correct += 1
        else:
            rep.mismatches.append(
                f"INPUT {c.label or c.text[:40]!r}: expected block={c.expect_block}, "
                f"got block={blocked} (score={v.score}, hard={v.hard_block})")
        if c.expect_block and blocked:
            rep.tp += 1
        elif not c.expect_block and blocked:
            rep.fp += 1
        elif not c.expect_block and not blocked:
            rep.tn += 1
        else:
            rep.fn += 1

    for c in (output_cases or []):
        v = policy.inspect_output(c.text, ctx)
        rep.output_total += 1
        if v.acceptable == c.expect_acceptable:
            rep.output_correct += 1
        else:
            rep.mismatches.append(
                f"OUTPUT {c.label or c.text[:40]!r}: expected acceptable={c.expect_acceptable}, "
                f"got acceptable={v.acceptable} (violations={list(v.violations)})")

    return rep
