"""
test_reinspection.py - regression tests for the 2026-10-28 reinspection
=======================================================================
Each test failed on HEAD 390860a and passes with its fix.
"""
import asyncio
import os
import subprocess
import sys
from pathlib import Path

import pytest

import gsa_gateway as G
from gsa_gateway import Gateway, mock_inference_gateway

ROOT = Path(__file__).resolve().parent


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# Step 1: an upstream failure (outcome 502) must not be labelled OK by /evaluate
def test_evaluate_labels_upstream_error_not_ok():
    async def _t():
        async def boom(_prompt):
            raise ValueError("bad upstream")
        saved = G.gateway.generator
        G.gateway.generator = boom
        await G.gateway.start()
        try:
            body = await G.evaluate(
                payload=G.EvaluationRequest(request_text="Generate a compliant status report metrics profile."),
                tenant_id="tenant_UE")
            assert body["status"] == "UPSTREAM_ERROR"
            assert body["response"] is None
        finally:
            G.gateway.generator = saved
            await G.gateway.stop()
    run(_t())


# Step 2: only the dev profile may accept unsigned bearer tokens; a typo in the profile is not dev
@pytest.mark.parametrize("profile", ["staging", "production", "Prod", "test", ""])
def test_only_dev_profile_allows_dev_bearer_fallback(tmp_path, profile):
    clean = {k: v for k, v in os.environ.items() if not k.startswith("GSA_")}
    clean.update(GSA_ENV=profile, GSA_SECRET_KEY="a-real-secret", GSA_AUDIT_DB_PATH=str(tmp_path / "a.db"))
    code = "import gsa_gateway as g; print(g.AUTHENTICATOR.allow_dev_fallback)"
    done = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=clean, capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "False"


# Step 3: feedback on one trace is counted once, so repeats cannot pump the shared threshold
def test_repeated_feedback_on_one_trace_counts_once():
    async def _t():
        g = Gateway(mock_inference_gateway)
        await g.start()
        try:
            base = g.threshold_controller.threshold
            b = await g.process("bypass override", tenant_id="t4")
            assert b.risk.blocked
            for _ in range(15):
                assert await g.record_feedback(b.trace_id, "t4", was_actually_risky=False) is True
            assert g.threshold_controller.total_feedback == 1
            assert g.threshold_controller.threshold == base
        finally:
            await g.stop()
    run(_t())


# Step 4: a truncated chain does not verify (genesis anchor; stored head when supplied)
def test_truncated_chain_does_not_verify():
    async def _t():
        g = Gateway(mock_inference_gateway)
        await g.start()
        try:
            for i in range(3):
                await g.process(f"Generate a compliant status report {i}.", tenant_id="t5")
            head = g.ledger.chain[-1]["hash"]
            assert g.ledger.verify_chain() and g.ledger.verify_chain(expected_head=head)
            del g.ledger.chain[-1]
            assert g.ledger.verify_chain(expected_head=head) is False     # tail cut: needs the anchor
            del g.ledger.chain[0]
            assert g.ledger.verify_chain() is False                        # head cut: genesis gone
        finally:
            await g.stop()
    run(_t())


# An output the policy rejects on every attempt is blocked (403, no text), not released with a flag
def test_rejected_output_is_not_released_after_retries():
    class RejectAll(G.BaselinePolicy):
        name = "reject-all"

        def inspect_output(self, text, ctx=None):
            return G.OutputVerdict(acceptable=False, violations=["unsafe content"], flags={"unsafe": True})

    async def _t():
        g = Gateway(mock_inference_gateway, policy=RejectAll())
        g.pipeline.enforce_style = True
        saved = G.gateway
        G.gateway = g
        await g.start()
        try:
            body = await G.evaluate(
                payload=G.EvaluationRequest(request_text="Generate a compliant status report metrics profile."),
                tenant_id="t_rej")
            assert body["status"] == "BLOCKED"
            assert body["response"] is None
            assert body["attestation"] is None
            assert body["style"] == {"unsafe": True}
            b = await g.get_trace(body["trace_id"])
            assert b.outcome.response is None
            assert b.outcome.status == 403
            assert b.outcome.attempts == G.MAX_CORRECTION_ATTEMPTS
            assert "not satisfied" in b.outcome.note
            assert b.audit.ledger_index == len(g.ledger.chain) and g.ledger.verify_chain()
        finally:
            G.gateway = saved
            await g.stop()
    run(_t())


# The default (advisory) path is unchanged: with enforce_style off a rejecting policy still releases the text
def test_advisory_default_still_releases_rejected_output():
    class RejectAll(G.BaselinePolicy):
        name = "reject-all"

        def inspect_output(self, text, ctx=None):
            return G.OutputVerdict(acceptable=False, violations=["unsafe content"], flags={})

    async def _t():
        g = Gateway(mock_inference_gateway, policy=RejectAll())
        assert g.pipeline.enforce_style is False
        await g.start()
        try:
            b = await g.process("Generate a compliant status report metrics profile.", tenant_id="t_adv")
            assert b.outcome.status == 200 and b.outcome.response
            assert b.outcome.style_enforced is False
        finally:
            await g.stop()
    run(_t())
