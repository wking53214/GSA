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
