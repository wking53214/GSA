"""GSA's decisions and audit records as things a CNS verdict can be bound to.

These skip where ``cns`` is not installed. CI installs requirements-cns.txt and sets GSA_REQUIRE_CNS=1, so there they
cannot skip. Binding only: nothing here is a gate and nothing maps to a verdict.

Run:  pytest -q test_cns_connector.py
"""
import asyncio
import copy
import dataclasses
import hashlib
import json
import os

import pytest

if os.environ.get("GSA_REQUIRE_CNS") == "1":  # CI: a missing cns is a failure, not a skip
    import cns.gate as gate
else:
    gate = pytest.importorskip("cns.gate")

from gsa_cns_connector import (  # noqa: E402
    AUDIT_RECORD_SUBJECT, DECISION_SUBJECT, audit_record_binds, audit_record_content, audit_record_digest, binds,
    cns_available, decision_content, decision_digest)
from gsa_gateway import AuditRecord, ExecutionOutcome, Gateway, RiskAssessment, TraceBundle  # noqa: E402
from persistence import make_store  # noqa: E402
from policy_api import BasePolicy, InputVerdict  # noqa: E402

CANARY = "CANARY-5b8e12d4-private-tenant-text"


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def trace_dict():
    """A served decision, in the dict form the audit store keeps (asdict of a TraceBundle)."""
    return {
        "trace_id": "TR-AB12CD34",
        "tenant_id": "tenant-a",
        "request_text": f"Summarise the incident. {CANARY}",
        "risk": {"blocked": False, "score": 0.25, "reasons": ["risk tokens: incident"], "threshold_used": 0.8,
                 "hard_block": False, "contributing_members": ["baseline", "financial"]},
        "outcome": {"status": 200, "session_id": "GSA-1A2B3C", "response": f"Latency fell 22% because of caching. {CANARY}",
                    "attempts": 2, "style_enforced": True, "style_report": {"first_person": [], "grounded": True},
                    "telemetry": {"entropy": 1.16, "risk_score": 0.25},
                    "attestation": {"forensic_sig": "a" * 64, "auth_tag": "b" * 64,
                                    "signed_at": "2026-10-17T10:00:00+00:00", "nonce": "0123456789abcdef"},
                    "runtime_ms": 3.5, "note": ""},
        "health": {"status": "NEUTRAL", "regime": "STABLE", "energy": 0.1, "trend": 0.0, "resilience": 0.9, "details": {}},
        "audit": {"trace_id": "TR-AB12CD34", "timestamp": "2026-10-17T10:00:01+00:00", "ledger_index": 7,
                  "payload_hash": "c" * 64, "policy_name": "baseline", "policy_version": "1.0.0"},
    }


def blocked_dict():
    d = trace_dict()
    d["risk"].update(blocked=True, hard_block=True, score=1.0, reasons=["prompt-injection pattern"])
    d["outcome"].update(status=403, response=None, attempts=0, style_enforced=False, style_report=None,
                        telemetry=None, attestation=None, note="blocked: prompt-injection pattern")
    return d


def bundle_of(d):
    """The same decision as the repo's own dataclasses."""
    return TraceBundle(
        trace_id=d["trace_id"], tenant_id=d["tenant_id"], request_text=d["request_text"],
        risk=RiskAssessment(**d["risk"]), outcome=ExecutionOutcome(**d["outcome"]), health=d["health"],
        audit=AuditRecord(**d["audit"]))


def issued_against(subject, digest):
    return gate.GateResult(gate="test.gate", position=gate.GatePosition.OMEGA, outcome=gate.GateOutcome.PASS,
                           reason="issued for the test", subject=subject, subject_digest=digest)


def conforms(value):
    """Only what cns.gate accepts: str, int, float, bool, None, list, and dicts with str keys."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return True
    if isinstance(value, list):
        return all(conforms(v) for v in value)
    if isinstance(value, dict):
        return all(isinstance(k, str) and conforms(v) for k, v in value.items())
    return False


def run(coro):
    return asyncio.run(coro)


def test_cns_is_reported_available():
    assert cns_available() is True


# ------------------------------------------------------------ determinism and shape

def test_the_same_decision_gives_the_same_content_and_digest():
    assert decision_content(trace_dict()) == decision_content(copy.deepcopy(trace_dict()))
    assert decision_digest(trace_dict()) == decision_digest(trace_dict())
    assert audit_record_digest(trace_dict()["audit"]) == audit_record_digest(trace_dict()["audit"])


def test_the_digest_is_cns_subject_digest_over_the_content():
    assert decision_digest(trace_dict()) == gate.subject_digest(decision_content(trace_dict()))
    audit = trace_dict()["audit"]
    assert audit_record_digest(audit) == gate.subject_digest(audit_record_content(audit))


def test_the_repos_dataclasses_and_their_dict_form_give_the_same_content():
    assert decision_content(bundle_of(trace_dict())) == decision_content(trace_dict())
    assert decision_content(bundle_of(blocked_dict())) == decision_content(blocked_dict())
    assert audit_record_content(AuditRecord(**trace_dict()["audit"])) == audit_record_content(trace_dict()["audit"])


def test_a_decision_survives_the_json_round_trip_the_store_applies():
    stored = json.loads(json.dumps(dataclasses.asdict(bundle_of(trace_dict()))))
    assert decision_digest(stored) == decision_digest(trace_dict())


def test_content_holds_only_types_cns_accepts_and_cns_can_digest_it():
    for content in (decision_content(trace_dict()), decision_content(blocked_dict()),
                    audit_record_content(trace_dict()["audit"])):
        assert conforms(content), content
        assert len(gate.subject_digest(content)) == 64


def test_a_blocked_decision_is_recorded_as_the_gateway_made_it():
    content = decision_content(blocked_dict())
    assert content["outcome"]["status"] == 403 and content["risk"]["blocked"] is True
    assert content["outcome"]["response_sha256"] is None and content["outcome"]["attestation"] is None
    assert decision_digest(blocked_dict()) != decision_digest(trace_dict())


def test_the_two_kinds_of_output_do_not_share_a_digest():
    assert decision_digest(trace_dict()) != audit_record_digest(trace_dict()["audit"])


# ------------------------------------------------------------ every bound field is bound

def _set(path, value):
    def mutate(d):
        target = d
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
        return d
    return mutate


DECISION_CHANGES = {
    "trace_id": _set(["trace_id"], "TR-00000000"),
    "tenant_id": _set(["tenant_id"], "tenant-b"),
    "tenant_id removed": _set(["tenant_id"], None),
    "request_text": _set(["request_text"], "A different request."),
    "risk.blocked": _set(["risk", "blocked"], True),
    "risk.score": _set(["risk", "score"], 0.26),
    "risk.threshold_used": _set(["risk", "threshold_used"], 0.79),
    "risk.hard_block": _set(["risk", "hard_block"], True),
    "risk.reasons changed": _set(["risk", "reasons"], ["raw SSN present"]),
    "risk.reasons added": lambda d: d["risk"]["reasons"].append("another") or d,
    "risk.reasons emptied": _set(["risk", "reasons"], []),
    "risk.contributing_members added": lambda d: d["risk"]["contributing_members"].append("jailbreak") or d,
    "risk.contributing_members dropped": lambda d: d["risk"]["contributing_members"].pop() and d,
    "outcome.status": _set(["outcome", "status"], 502),
    "outcome.session_id": _set(["outcome", "session_id"], "GSA-FFFFFF"),
    "outcome.response": _set(["outcome", "response"], "A different response."),
    "outcome.response removed": _set(["outcome", "response"], None),
    "outcome.attempts": _set(["outcome", "attempts"], 3),
    "outcome.style_enforced": _set(["outcome", "style_enforced"], False),
    "outcome.style_report value": _set(["outcome", "style_report", "grounded"], False),
    "outcome.style_report key": _set(["outcome", "style_report", "fluff"], ["very"]),
    "outcome.style_report removed": _set(["outcome", "style_report"], None),
    "outcome.telemetry.entropy": _set(["outcome", "telemetry", "entropy"], 1.17),
    "outcome.telemetry.risk_score": _set(["outcome", "telemetry", "risk_score"], 0.5),
    "outcome.telemetry removed": _set(["outcome", "telemetry"], None),
    "attestation.forensic_sig": _set(["outcome", "attestation", "forensic_sig"], "d" * 64),
    "attestation.auth_tag": _set(["outcome", "attestation", "auth_tag"], "d" * 64),
    "attestation.signed_at": _set(["outcome", "attestation", "signed_at"], "2026-10-17T10:00:01+00:00"),
    "attestation.nonce": _set(["outcome", "attestation", "nonce"], "fedcba9876543210"),
    "attestation removed": _set(["outcome", "attestation"], None),
    "outcome.note": _set(["outcome", "note"], "output policy not satisfied after retries"),
    "audit.trace_id": _set(["audit", "trace_id"], "TR-00000000"),
    "audit.timestamp": _set(["audit", "timestamp"], "2026-10-17T10:00:02+00:00"),
    "audit.ledger_index": _set(["audit", "ledger_index"], 8),
    "audit.payload_hash": _set(["audit", "payload_hash"], "d" * 64),
    "audit.policy_name": _set(["audit", "policy_name"], "financial"),
    "audit.policy_version": _set(["audit", "policy_version"], "1.0.1"),
}


@pytest.mark.parametrize("name", list(DECISION_CHANGES))
def test_changing_any_bound_decision_field_changes_the_digest(name):
    assert decision_digest(DECISION_CHANGES[name](trace_dict())) != decision_digest(trace_dict())


AUDIT_CHANGES = {
    "trace_id": ("trace_id", "TR-00000000"), "timestamp": ("timestamp", "2026-10-17T10:00:02+00:00"),
    "ledger_index": ("ledger_index", 8), "payload_hash": ("payload_hash", "d" * 64),
    "policy_name": ("policy_name", "financial"), "policy_version": ("policy_version", "1.0.1"),
}


@pytest.mark.parametrize("name", list(AUDIT_CHANGES))
def test_changing_any_bound_audit_field_changes_the_digest(name):
    key, value = AUDIT_CHANGES[name]
    changed = {**trace_dict()["audit"], key: value}
    assert audit_record_digest(changed) != audit_record_digest(trace_dict()["audit"])


# ------------------------------------------------------------ what is claimed not to matter

def test_latency_and_gateway_health_are_not_part_of_a_decision():
    base = decision_digest(trace_dict())
    other = trace_dict()
    other["outcome"]["runtime_ms"] = 900.0
    other["health"] = {"status": "RISK_INCREASING", "regime": "ATTACKED", "energy": 9.0}
    assert decision_digest(other) == base
    del other["health"], other["outcome"]["runtime_ms"]
    assert decision_digest(other) == base


def test_extra_keys_container_kinds_and_key_order_are_not_part_of_a_decision():
    base = decision_digest(trace_dict())
    noisy = trace_dict()
    noisy["extra"] = {"anything": [1, 2]}
    noisy["risk"]["extra"] = 1
    noisy["outcome"]["extra"] = 1
    noisy["audit"]["extra"] = 1
    noisy["outcome"]["attestation"]["extra"] = 1
    noisy["outcome"]["telemetry"]["extra"] = 1
    assert decision_digest(noisy) == base
    tupled = trace_dict()
    tupled["risk"]["reasons"] = tuple(tupled["risk"]["reasons"])
    tupled["outcome"]["style_report"]["first_person"] = ()
    assert decision_digest(tupled) == base
    assert conforms(decision_content(tupled)) and decision_content(tupled)["risk"]["reasons"] == ["risk tokens: incident"]
    assert decision_content(tupled)["outcome"]["style_report"]["first_person"] == []
    assert decision_digest(dict(reversed(list(trace_dict().items())))) == base


def test_contributing_members_are_a_set_so_their_order_is_not_bound_but_reasons_are_ordered():
    base = decision_digest(trace_dict())
    swapped = trace_dict()
    swapped["risk"]["contributing_members"].reverse()
    assert decision_digest(swapped) == base
    two_reasons = trace_dict()
    two_reasons["risk"]["reasons"] = ["a", "b"]
    reversed_reasons = trace_dict()
    reversed_reasons["risk"]["reasons"] = ["b", "a"]
    assert decision_digest(two_reasons) != decision_digest(reversed_reasons)


def test_a_number_is_the_same_whether_it_is_an_int_or_a_float():
    ints = trace_dict()
    ints["risk"].update(score=1, threshold_used=1)
    floats = trace_dict()
    floats["risk"].update(score=1.0, threshold_used=1.0)
    assert decision_digest(ints) == decision_digest(floats)


def test_older_stored_traces_without_the_later_risk_fields_still_bind():
    old = trace_dict()
    for key in ("threshold_used", "hard_block", "contributing_members"):
        del old["risk"][key]
    content = decision_content(old)
    assert content["risk"]["hard_block"] is False and content["risk"]["contributing_members"] == []
    assert content["risk"]["threshold_used"] is None
    del old["outcome"]["note"], old["audit"]["policy_name"], old["audit"]["policy_version"]
    assert decision_content(old)["outcome"]["note"] == "" and decision_content(old)["audit"]["policy_name"] == ""


def test_a_lone_surrogate_in_a_request_hashes_instead_of_raising():
    d = trace_dict()
    d["request_text"] = "broken \ud83d request"
    assert len(decision_digest(d)) == 64


# ------------------------------------------------------------ wrong types and missing keys

@pytest.mark.parametrize("bad", [None, "text", 7, ["trace_id"], (1, 2), object, int, TraceBundle, AuditRecord])
def test_a_decision_that_is_neither_a_dataclass_nor_a_mapping_is_a_type_error(bad):
    with pytest.raises(TypeError, match="dataclass instance or a mapping"):
        decision_content(bad)
    with pytest.raises(TypeError, match="dataclass instance or a mapping"):
        audit_record_content(bad)


@pytest.mark.parametrize("path, value", [
    (["trace_id"], 7), (["tenant_id"], 7), (["request_text"], 7), (["request_text"], None), (["request_text"], b"x"),
    (["risk"], "blocked"), (["risk"], None), (["outcome"], 200), (["audit"], "TR-1"),
    (["risk", "blocked"], "yes"), (["risk", "blocked"], 1), (["risk", "score"], "0.25"), (["risk", "score"], True),
    (["risk", "threshold_used"], "0.8"), (["risk", "hard_block"], 0), (["risk", "reasons"], "prompt-injection"),
    (["risk", "reasons"], [1]), (["risk", "contributing_members"], "baseline"), (["risk", "contributing_members"], [3]),
    (["outcome", "status"], "200"), (["outcome", "status"], True), (["outcome", "status"], 200.0),
    (["outcome", "session_id"], 5), (["outcome", "response"], 5), (["outcome", "attempts"], "2"),
    (["outcome", "style_enforced"], "True"), (["outcome", "style_report"], ["a"]), (["outcome", "style_report"], {1: 2}),
    (["outcome", "style_report"], {"a": {1, 2}}), (["outcome", "style_report"], {"a": object()}),
    (["outcome", "telemetry"], [1.0, 2.0]), (["outcome", "telemetry", "entropy"], "1.0"),
    (["outcome", "telemetry", "risk_score"], None), (["outcome", "attestation"], "sig"),
    (["outcome", "attestation", "forensic_sig"], 5), (["outcome", "attestation", "auth_tag"], None),
    (["outcome", "attestation", "signed_at"], 1.5), (["outcome", "attestation", "nonce"], 12),
    (["outcome", "note"], None), (["audit", "ledger_index"], "7"), (["audit", "ledger_index"], True),
    (["audit", "timestamp"], 1.0), (["audit", "payload_hash"], 5), (["audit", "policy_name"], None),
    (["audit", "policy_version"], 1)])
def test_a_field_of_the_wrong_type_is_a_type_error(path, value):
    with pytest.raises(TypeError):
        decision_content(_set(path, value)(trace_dict()))


@pytest.mark.parametrize("field, value", [("trace_id", 1), ("timestamp", 2), ("ledger_index", "7"), ("ledger_index", False),
                                          ("payload_hash", None), ("policy_name", 3), ("policy_version", 4)])
def test_an_audit_field_of_the_wrong_type_is_a_type_error(field, value):
    with pytest.raises(TypeError):
        audit_record_content({**trace_dict()["audit"], field: value})


REQUIRED = [["trace_id"], ["request_text"], ["risk"], ["outcome"], ["audit"],
            ["risk", "blocked"], ["risk", "score"], ["risk", "reasons"],
            ["outcome", "status"], ["outcome", "session_id"], ["outcome", "response"], ["outcome", "attempts"],
            ["outcome", "style_enforced"], ["outcome", "style_report"], ["outcome", "telemetry"],
            ["outcome", "attestation"],
            ["outcome", "telemetry", "entropy"], ["outcome", "telemetry", "risk_score"],
            ["outcome", "attestation", "forensic_sig"], ["outcome", "attestation", "auth_tag"],
            ["outcome", "attestation", "signed_at"], ["outcome", "attestation", "nonce"],
            ["audit", "trace_id"], ["audit", "timestamp"], ["audit", "ledger_index"], ["audit", "payload_hash"]]


@pytest.mark.parametrize("path", REQUIRED, ids=lambda p: ".".join(p))
def test_a_missing_required_key_is_a_value_error_naming_it(path):
    d = trace_dict()
    target = d
    for key in path[:-1]:
        target = target[key]
    del target[path[-1]]
    with pytest.raises(ValueError, match=path[-1]):
        decision_content(d)


@pytest.mark.parametrize("key", ["trace_id", "timestamp", "ledger_index", "payload_hash"])
def test_an_audit_record_missing_a_required_key_is_a_value_error_naming_it(key):
    audit = trace_dict()["audit"]
    del audit[key]
    with pytest.raises(ValueError, match=key):
        audit_record_content(audit)


def test_the_error_names_where_the_key_is_missing():
    d = trace_dict()
    del d["outcome"]["attestation"]["nonce"]
    with pytest.raises(ValueError, match=r"outcome\.attestation\.nonce"):
        decision_content(d)
    d = trace_dict()
    del d["risk"]["score"]
    with pytest.raises(ValueError, match=r"risk\.score"):
        decision_content(d)


# ------------------------------------------------------------ binds

def test_a_verdict_issued_against_exactly_this_decision_binds_to_it():
    result = issued_against(DECISION_SUBJECT, decision_digest(trace_dict()))
    assert binds(result, trace_dict()) is True
    assert binds(result, bundle_of(trace_dict())) is True
    assert result.binds(DECISION_SUBJECT, decision_digest(trace_dict()))


def test_a_verdict_does_not_bind_to_a_different_decision():
    result = issued_against(DECISION_SUBJECT, decision_digest(trace_dict()))
    assert binds(result, blocked_dict()) is False
    assert binds(result, DECISION_CHANGES["outcome.response"](trace_dict())) is False
    assert binds(result, DECISION_CHANGES["attestation.nonce"](trace_dict())) is False


def test_a_verdict_does_not_bind_under_another_subject():
    result = issued_against(DECISION_SUBJECT, decision_digest(trace_dict()))
    assert binds(result, trace_dict(), subject="some.other.subject") is False
    other = issued_against("some.other.subject", decision_digest(trace_dict()))
    assert binds(other, trace_dict()) is False
    assert binds(other, trace_dict(), subject="some.other.subject") is True


def test_a_verdict_on_an_audit_record_binds_to_that_record_only():
    audit = trace_dict()["audit"]
    result = issued_against(AUDIT_RECORD_SUBJECT, audit_record_digest(audit))
    assert audit_record_binds(result, audit) is True
    assert audit_record_binds(result, AuditRecord(**audit)) is True
    assert audit_record_binds(result, {**audit, "ledger_index": 8}) is False
    assert audit_record_binds(result, audit, subject="some.other.subject") is False
    assert audit_record_binds(issued_against(DECISION_SUBJECT, audit_record_digest(audit)), audit) is False


def test_a_decision_verdict_does_not_bind_to_its_audit_record_or_the_reverse():
    decision = issued_against(DECISION_SUBJECT, decision_digest(trace_dict()))
    audit = issued_against(AUDIT_RECORD_SUBJECT, audit_record_digest(trace_dict()["audit"]))
    assert audit_record_binds(decision, trace_dict()["audit"]) is False
    assert binds(audit, trace_dict()) is False


def test_an_unbound_hand_built_verdict_binds_to_nothing():
    unbound = gate.GateResult(gate="test.gate", position=gate.GatePosition.OMEGA, outcome=gate.GateOutcome.PASS)
    assert not unbound.bound()
    assert binds(unbound, trace_dict()) is False
    assert audit_record_binds(unbound, trace_dict()["audit"]) is False
    no_digest = gate.GateResult(gate="g", position=gate.GatePosition.OMEGA, outcome=gate.GateOutcome.PASS,
                                subject=DECISION_SUBJECT)
    assert binds(no_digest, trace_dict()) is False


@pytest.mark.parametrize("bad", [None, "pass", {"subject": "x"}, True])
def test_binds_takes_a_gate_result(bad):
    with pytest.raises(TypeError, match="GateResult"):
        binds(bad, trace_dict())
    with pytest.raises(TypeError, match="GateResult"):
        audit_record_binds(bad, trace_dict()["audit"])


def test_binds_rejects_an_output_it_cannot_read():
    result = issued_against(DECISION_SUBJECT, decision_digest(trace_dict()))
    with pytest.raises(TypeError):
        binds(result, "not a decision")
    with pytest.raises(ValueError, match="risk"):
        binds(result, {"trace_id": "x", "request_text": "y", "outcome": {}, "audit": {}})
    with pytest.raises(TypeError):
        audit_record_binds(result, None)


# ------------------------------------------------------------ tenant text is never copied

def test_no_tenant_text_appears_in_any_content():
    for content in (decision_content(trace_dict()), decision_content(blocked_dict()),
                    decision_content(bundle_of(trace_dict()))):
        assert CANARY not in repr(content)
        assert "Summarise the incident" not in repr(content) and "Latency fell" not in repr(content)
    content = decision_content(trace_dict())
    assert content["request_sha256"] == sha(trace_dict()["request_text"])
    assert content["outcome"]["response_sha256"] == sha(trace_dict()["outcome"]["response"])


def test_the_identity_and_the_attestation_fields_are_kept_as_they_are():
    content = decision_content(trace_dict())
    assert (content["trace_id"], content["tenant_id"]) == ("TR-AB12CD34", "tenant-a")
    assert content["outcome"]["attestation"] == trace_dict()["outcome"]["attestation"]
    assert content["audit"]["payload_hash"] == "c" * 64 and content["audit"]["policy_name"] == "baseline"
    assert "health" not in content and "runtime_ms" not in content["outcome"]


# ------------------------------------------------------------ against GSA's own code

class EchoPolicy(BasePolicy):
    name = "echo"
    version = "9.9.9"

    def assess_input(self, request, context):
        return InputVerdict(score=1.0, hard_block=True, reasons=["deny-all policy"]) if "FORBID" in request \
            else InputVerdict(score=0.1, reasons=["seen"])


async def canary_generator(prompt):
    return f"Throughput held steady because token consumption fell 22%. {CANARY}"


async def _serve(tmp_path, request, tenant="tenant-a"):
    store = make_store("sqlite", str(tmp_path / "audit.db"))
    gateway = Gateway(canary_generator, policy=EchoPolicy(), store=store)
    await gateway.start()
    try:
        bundle = await gateway.process(f"{request} {CANARY}", tenant_id=tenant)
        stored = store.get_trace(bundle.trace_id)
        return bundle, stored["bundle"], gateway
    finally:
        await gateway.stop()
        store.close()


def test_a_real_served_request_binds_and_the_stored_trace_gives_the_same_digest(tmp_path):
    bundle, stored, _gateway = run(_serve(tmp_path, "Report the throughput."))
    assert bundle.outcome.status == 200 and bundle.outcome.attestation and CANARY in bundle.outcome.response
    content = decision_content(bundle)
    assert conforms(content) and CANARY not in repr(content)
    assert content["audit"]["policy_name"] == "echo" and content["audit"]["policy_version"] == "9.9.9"
    assert content["tenant_id"] == "tenant-a" and content["risk"]["reasons"] == ["seen"]
    assert decision_digest(stored) == decision_digest(bundle)

    verdict = issued_against(DECISION_SUBJECT, decision_digest(bundle))
    assert binds(verdict, bundle) and binds(verdict, stored)
    tampered = copy.deepcopy(stored)
    tampered["outcome"]["response"] += " (edited afterwards)"
    assert not binds(verdict, tampered)
    forged = copy.deepcopy(stored)
    forged["outcome"]["attestation"]["auth_tag"] = "0" * 64
    assert not binds(verdict, forged)
    assert not binds(verdict, {**stored, "tenant_id": "tenant-b"}) and not binds(verdict, {**stored, "trace_id": "TR-0"})


def test_a_real_audit_record_binds(tmp_path):
    bundle, stored, gateway = run(_serve(tmp_path, "Report the throughput."))
    assert isinstance(bundle.audit, AuditRecord)
    verdict = issued_against(AUDIT_RECORD_SUBJECT, audit_record_digest(bundle.audit))
    assert audit_record_binds(verdict, bundle.audit) and audit_record_binds(verdict, stored["audit"])
    assert audit_record_content(bundle.audit)["ledger_index"] == len(gateway.ledger.chain)
    assert not audit_record_binds(verdict, {**stored["audit"], "payload_hash": "0" * 64})


def test_a_real_blocked_request_binds_and_differs_from_a_served_one(tmp_path):
    served, _, _ = run(_serve(tmp_path, "Report the throughput."))
    blocked, stored, _ = run(_serve(tmp_path, "FORBID this."))
    assert blocked.outcome.status == 403 and blocked.outcome.response is None
    content = decision_content(blocked)
    assert content["risk"]["blocked"] is True and content["risk"]["hard_block"] is True
    assert content["outcome"]["attestation"] is None and CANARY not in repr(content)
    verdict = issued_against(DECISION_SUBJECT, decision_digest(blocked))
    assert binds(verdict, blocked) and binds(verdict, stored)
    assert not binds(verdict, served)
