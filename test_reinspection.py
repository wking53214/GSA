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
