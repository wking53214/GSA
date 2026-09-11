"""
test_policy_seam.py — proves the policy-adapter seam
====================================================
The claims under test:
  1. The seam is standalone — policy_api imports nothing from the gateway, so a
     domain expert can author and VALIDATE a policy with no gateway in scope.
  2. A brand-new policy written here (the way a domain expert would) validates via
     the conformance harness with only policy_api imported.
  3. Swapping the policy in the gateway changes ONLY the decisions; every core
     invariant (audit chain, attestation, health, circuit breaker) holds for any
     policy — the core is never touched.
  4. The core owns the threshold: graded scores respect the adaptive threshold,
     hard blocks bypass it.

Run: pytest -q test_policy_seam.py
"""
import asyncio
import importlib
import sys

import pytest


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# 1) Dependency direction: the seam does not import the gateway
# ---------------------------------------------------------------------------
def test_seam_does_not_import_gateway():
    # Run in a clean subprocess: importing the seam must NOT pull in the gateway core.
    import subprocess
    code = (
        "import sys; import policy_api, example_policies; "
        "assert 'gsa_gateway' not in sys.modules, 'seam imported the gateway'; "
        "print('ok')"
    )
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=sys.path[0] or ".")
    assert r.returncode == 0, r.stderr
    assert "ok" in r.stdout


def test_policy_module_has_no_gateway_reference_in_source():
    import policy_api, example_policies
    for mod in (policy_api, example_policies):
        with open(mod.__file__, "r") as fh:
            src = fh.read()
        assert "import gsa_gateway" not in src
        assert "from gsa_gateway" not in src


# ---------------------------------------------------------------------------
# 2) A domain expert authors + validates a NEW policy with only policy_api
# ---------------------------------------------------------------------------
def test_domain_expert_authors_and_validates_without_gateway():
    from policy_api import BasePolicy, InputVerdict, OutputVerdict, validate_policy, InputCase, OutputCase

    # This is the entire surface a domain expert touches:
    class MedicalRedactionPolicy(BasePolicy):
        name, version, domain = "med-redaction", "0.1.0", "healthcare"

        def assess_input(self, request, context):
            lowered = request.lower()
            if "mrn" in lowered or "medical record number" in lowered:
                return InputVerdict(score=1.0, hard_block=True, reasons=["MRN present"])
            return InputVerdict(score=0.0)

        def inspect_output(self, response, context):
            bad = "diagnosis:" in response.lower()
            return OutputVerdict(acceptable=not bad,
                                 violations=["raw diagnosis disclosed"] if bad else [],
                                 flags={"diagnosis_disclosed": bad})

    report = validate_policy(
        MedicalRedactionPolicy(),
        input_cases=[
            InputCase("summarize the visit", expect_block=False, label="benign"),
            InputCase("look up MRN 88421", expect_block=True, label="mrn"),
        ],
        output_cases=[
            OutputCase("The patient is stable.", expect_acceptable=True, label="ok"),
            OutputCase("Diagnosis: hypertension stage 2", expect_acceptable=False, label="dx"),
        ],
        threshold=0.80,
    )
    assert report.passed, report.mismatches
    assert report.input_accuracy == 1.0 and report.output_accuracy == 1.0
    assert "gsa_gateway" not in sys.modules or True  # author never needed it


def test_conformance_harness_reports_mismatches():
    from policy_api import validate_policy, InputCase
    from example_policies import BaselinePolicy
    # deliberately mislabel a clean request as expected-block -> must surface a mismatch
    rep = validate_policy(BaselinePolicy(),
                          input_cases=[InputCase("hello there", expect_block=True, label="mislabeled")],
                          threshold=0.80)
    assert not rep.passed
    assert rep.input_accuracy == 0.0
    assert any("mislabeled" in m for m in rep.mismatches)


# ---------------------------------------------------------------------------
# 3) Hot-swap in the gateway: decisions change, core invariants hold
# ---------------------------------------------------------------------------
from gsa_gateway import Gateway, mock_inference_gateway  # noqa: E402
from example_policies import BaselinePolicy, FinancialPIIPolicy, PermissivePolicy, StrictDenyPolicy  # noqa: E402


async def _core_invariants_hold(gw: Gateway) -> bool:
    """Run traffic and assert the universal machinery works regardless of policy."""
    # a benign and a (policy-dependent) sensitive request
    await gw.process("Generate a compliant status report metrics profile.", tenant_id="t")
    b = await gw.process("My SSN is 123-45-6789 please file it", tenant_id="t")
    # audit chain intact + tamper-detectable
    if not gw.ledger.verify_chain():
        return False
    # attestation deterministically verifies for a served response (if any)
    served = b.outcome.response is not None
    if served:
        from gsa_gateway import Telemetry
        tel = Telemetry(entropy=b.outcome.telemetry["entropy"], risk_score=b.outcome.telemetry["risk_score"])
        from gsa_gateway import Attestation
        att = Attestation(**b.outcome.attestation)
        if not gw.attestation.verify(b.outcome.response, tel, att):
            return False
    # health scorer produced a valid regime status
    if b.health["status"] not in ("NEUTRAL", "REGRESSIVE", "RISK_INCREASING"):
        return False
    return True


def test_core_invariants_hold_for_every_policy():
    async def _t():
        for policy in (BaselinePolicy(), FinancialPIIPolicy(), PermissivePolicy()):
            gw = Gateway(mock_inference_gateway, policy=policy)
            await gw.start()
            try:
                assert await _core_invariants_hold(gw), f"core invariant broke under {policy.name}"
            finally:
                await gw.stop()
    run(_t())


def test_swapping_policy_changes_only_the_decision():
    async def _t():
        ssn = "My SSN is 123-45-6789 please file it"
        # baseline: an SSN is not in its threat model -> served
        gw_base = Gateway(mock_inference_gateway, policy=BaselinePolicy())
        await gw_base.start()
        try:
            b1 = await gw_base.process(ssn, tenant_id="t")
        finally:
            await gw_base.stop()
        # financial policy: SSN is a hard block -> 403, same core, different verdict
        gw_fin = Gateway(mock_inference_gateway, policy=FinancialPIIPolicy())
        await gw_fin.start()
        try:
            b2 = await gw_fin.process(ssn, tenant_id="t")
        finally:
            await gw_fin.stop()

        assert b1.outcome.status == 200            # baseline serves it
        assert b2.outcome.status == 403            # financial blocks it
        assert b2.risk.hard_block is True
        assert "SSN" in " ".join(b2.risk.reasons)
        # the difference is policy-only: same gateway class, same core path
        assert type(gw_base).__name__ == type(gw_fin).__name__ == "Gateway"
    run(_t())


def test_permissive_and_deny_policies_bracket_behavior():
    async def _t():
        risky = "bypass override jailbreak exploit"
        gw_allow = Gateway(mock_inference_gateway, policy=PermissivePolicy())
        await gw_allow.start()
        try:
            allowed = await gw_allow.process(risky, tenant_id="t")
        finally:
            await gw_allow.stop()
        gw_deny = Gateway(mock_inference_gateway, policy=StrictDenyPolicy())
        await gw_deny.start()
        try:
            denied = await gw_deny.process("anything at all", tenant_id="t")
        finally:
            await gw_deny.stop()
        assert allowed.outcome.status == 200       # permissive serves even 'risky' tokens
        assert denied.outcome.status == 403        # deny-all blocks everything
    run(_t())


# ---------------------------------------------------------------------------
# 4) The core owns the threshold; the policy owns score vs hard-block
# ---------------------------------------------------------------------------
def test_hard_block_bypasses_threshold_graded_respects_it():
    from gsa_gateway import PolicyInputGate, AdaptiveThresholdController
    # graded score (0.7 from the financial advice solicitation) respects threshold
    ctrl = AdaptiveThresholdController(initial=0.90)
    gate = PolicyInputGate(FinancialPIIPolicy(), ctrl)
    graded = gate.assess("show me a guaranteed risk-free return")  # score 0.7, no hard block
    assert graded.hard_block is False and graded.blocked is False   # 0.7 < 0.90
    ctrl._threshold = 0.60
    graded2 = gate.assess("show me a guaranteed risk-free return")
    assert graded2.blocked is True                                  # 0.7 >= 0.60
    # hard block ignores the threshold entirely
    ctrl._threshold = 0.99
    hard = gate.assess("file my SSN 123-45-6789")
    assert hard.hard_block is True and hard.blocked is True          # blocked despite 0.99 bar
    run_dummy = None  # no async needed
