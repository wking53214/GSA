"""
example_policies.py — concrete policies authored against the seam
================================================================
Each policy imports ONLY policy_api. None of them imports the gateway. They are
exactly what a domain expert would write: a name/version/domain and the two
methods. The keyword/injection/style rules that used to live inside the gateway
now live here, in BaselinePolicy — the core no longer contains any domain rules.

Two real, different domains are shown to prove the seam:
  * BaselinePolicy        — generic LLM hygiene (injection + risk keywords; house-style output)
  * FinancialPIIPolicy    — bright-line PII blocking + financial-advice guardrails

Plus PermissivePolicy / StrictDenyPolicy used by the conformance tests.
"""
from __future__ import annotations

import re
from typing import List

from policy_api import BasePolicy, InputVerdict, OutputVerdict, PolicyContext


# ===========================================================================
# 1) Baseline generic policy (the rules formerly hard-coded in the gateway)
# ===========================================================================
_RISK_TOKENS = {"bypass", "override", "jailbreak", "exploit", "malware", "ransomware"}

_INJECTION_PATTERNS = [
    re.compile(r"ignore (all |the |your )?(previous|prior|above) (instructions|prompts?)", re.IGNORECASE),
    re.compile(r"disregard (all |the |your )?(previous|prior|above)", re.IGNORECASE),
    re.compile(r"(reveal|print|show|leak) (your |the )?(system prompt|instructions|api[_ ]?key|secret)", re.IGNORECASE),
    re.compile(r"you are now (a|an|in)\b", re.IGNORECASE),
]

_STYLE_RX = {
    "first_person": re.compile(r"\b(i|i'm|i've|we|we're|our|us|me|my)\b", re.IGNORECASE),
    "hedging": re.compile(r"\b(maybe|perhaps|possibly|might|i think|probably|sort of|kind of)\b", re.IGNORECASE),
    "abstract_verbs": re.compile(r"\b(leverage|utilize|optimize|streamline|enable|improve|enhance)\b", re.IGNORECASE),
    "fluff": re.compile(r"\b(very|really|actually|basically|literally|just|simply)\b", re.IGNORECASE),
    "grounding": re.compile(r"(\d|because|due to|caused by|results? in|leads? to)"),
}

_MAX_REQUEST_CHARS = 8000


def _hits(rx: re.Pattern, text: str) -> List[str]:
    return sorted({m.group(0).lower() for m in rx.finditer(text) if m.group(0)})


class BaselinePolicy(BasePolicy):
    """Generic LLM-traffic hygiene. Graded risk for keywords/injection; an empty
    request is a hard block. Output is held to a plain house style (no first
    person, no hedging, grounded in a cause or a number) — measured, never rewritten."""
    name = "baseline"
    version = "1.0.0"
    domain = "generic"

    def __init__(self, enforce_style_default: bool = True):
        self.enforce_style_default = enforce_style_default

    def assess_input(self, request: str, context: PolicyContext) -> InputVerdict:
        if not request or not request.strip():
            return InputVerdict(score=1.0, hard_block=True, reasons=["empty input"])

        score = 0.0
        reasons: List[str] = []
        tokens = {t.strip(".,;:!?\"'").lower() for t in request.split()}

        risky = sorted(tokens & _RISK_TOKENS)
        if risky:
            score = max(score, 0.95)
            reasons.append(f"risk tokens: {', '.join(risky)}")

        for pat in _INJECTION_PATTERNS:
            if pat.search(request):
                score = max(score, 0.95)
                reasons.append("prompt-injection pattern")
                break

        if len(request) > _MAX_REQUEST_CHARS:
            score = max(score, 0.85)
            reasons.append("payload over size limit")

        return InputVerdict(score=round(score, 4), reasons=reasons)

    def inspect_output(self, response: str, context: PolicyContext) -> OutputVerdict:
        flags = {
            "first_person": _hits(_STYLE_RX["first_person"], response),
            "hedging": _hits(_STYLE_RX["hedging"], response),
            "abstract_verbs": _hits(_STYLE_RX["abstract_verbs"], response),
            "fluff": _hits(_STYLE_RX["fluff"], response),
            "grounded": bool(_STYLE_RX["grounding"].search(response)),
        }
        violations: List[str] = []
        if flags["first_person"]:
            violations.append("first-person language")
        if flags["hedging"]:
            violations.append("hedging language")
        if not flags["grounded"]:
            violations.append("no causal/quantitative grounding")
        return OutputVerdict(acceptable=not violations, violations=violations, flags=flags)


# ===========================================================================
# 2) Financial-services / PII policy — a completely different domain
# ===========================================================================
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_PAN = re.compile(r"\b(?:\d[ -]?){13,16}\b")                 # card-like 13–16 digit runs
_ROUTING = re.compile(r"\brouting(?:\s*(?:number|no\.?|#))?\s*[:#]?\s*\d{9}\b", re.IGNORECASE)
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_ADVICE_SOLICIT = re.compile(r"\b(guarantee|guaranteed|risk[- ]?free|sure thing|can't lose|double your)\b", re.IGNORECASE)


def _luhn_ok(digits: str) -> bool:
    ds = [int(c) for c in digits if c.isdigit()]
    if len(ds) < 13:
        return False
    total, parity = 0, len(ds) % 2
    for i, d in enumerate(ds):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


class FinancialPIIPolicy(BasePolicy):
    """Bright-line PII handling for a financial-services deployment. Raw SSNs and
    valid card numbers are HARD blocks on input (never threshold-dependent).
    Output must not echo PII and must not make guaranteed-return claims."""
    name = "financial-pii"
    version = "1.0.0"
    domain = "financial-services"

    def assess_input(self, request: str, context: PolicyContext) -> InputVerdict:
        if not request or not request.strip():
            return InputVerdict(score=1.0, hard_block=True, reasons=["empty input"])

        reasons: List[str] = []
        hard = False
        score = 0.0

        if _SSN.search(request):
            hard = True
            reasons.append("raw SSN present")
        for m in _PAN.finditer(request):
            if _luhn_ok(m.group(0)):
                hard = True
                reasons.append("valid payment card number present")
                break
        if _ROUTING.search(request):
            hard = True
            reasons.append("bank routing number present")

        if _ADVICE_SOLICIT.search(request):
            score = max(score, 0.7)
            reasons.append("solicitation of guaranteed-return advice")

        return InputVerdict(score=round(score, 4), hard_block=hard, reasons=reasons)

    def inspect_output(self, response: str, context: PolicyContext) -> OutputVerdict:
        violations: List[str] = []
        flags = {
            "ssn_echo": bool(_SSN.search(response)),
            "card_echo": any(_luhn_ok(m.group(0)) for m in _PAN.finditer(response)),
            "email_echo": bool(_EMAIL.search(response)),
            "guaranteed_claim": bool(_ADVICE_SOLICIT.search(response)),
        }
        if flags["ssn_echo"]:
            violations.append("output echoes an SSN")
        if flags["card_echo"]:
            violations.append("output echoes a payment card number")
        if flags["guaranteed_claim"]:
            violations.append("output makes a guaranteed-return claim")
        return OutputVerdict(acceptable=not violations, violations=violations, flags=flags)


# ===========================================================================
# 3) Trivial policies for conformance / non-interference tests
# ===========================================================================
class PermissivePolicy(BasePolicy):
    name, version, domain = "permissive", "1.0.0", "test"
    # inherits: never blocks, always accepts


class StrictDenyPolicy(BasePolicy):
    name, version, domain = "strict-deny", "1.0.0", "test"

    def assess_input(self, request: str, context: PolicyContext) -> InputVerdict:
        return InputVerdict(score=1.0, hard_block=True, reasons=["deny-all policy"])

    def inspect_output(self, response: str, context: PolicyContext) -> OutputVerdict:
        return OutputVerdict(acceptable=False, violations=["deny-all policy"])
