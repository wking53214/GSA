"""Optional connector to CNS (``cns.gate``): make GSA's decisions bindable.

GSA is independent. It has no runtime dependency on CNS, imports nothing from
CNS when it loads, and its whole suite passes with CNS absent. This module is
the one place that knows CNS exists, and it asks for CNS only when a digest is
requested. The ``*_content`` functions are pure and work without CNS; the
digest and ``binds`` functions raise :class:`CnsNotInstalled`, with the install
command, when CNS is missing. Nothing else in GSA is affected. This module also
imports nothing from the gateway, so it costs nothing to load.

Binding only
------------
CNS's shared gate contract is ``cns.gate.GateResult``. A verdict carries a
``subject`` label and a ``subject_digest``, and ``GateResult.binds`` says
whether the verdict was issued against exactly that content. This module lets
a verdict about a GSA output be checked against the output: nothing more. It is
not a gate, it maps nothing to a verdict, and it takes no position on whether
the gateway decided well. The gateway's own decision (``outcome.status``,
``risk.blocked``) is recorded as it is, not reinterpreted.

What is bound
-------------
* A gateway decision (:func:`decision_content`): a ``gsa_gateway.TraceBundle``,
  or the dict the audit store keeps for it (``asdict(bundle)``, which is what
  ``store.get_trace(...)["bundle"]`` returns, so a stored trace and the live
  object give the same digest). It binds the tenant, the request hash, the
  risk assessment, the outcome (status, session, attempts, the response hash,
  the style report, the attestation inputs and the attestation itself) and the
  audit record.
* An audit record (:func:`audit_record_content`): a ``gsa_gateway.AuditRecord``
  or its dict. It binds the trace id, timestamp, ledger index, payload hash and
  the policy name and version.

Left out on purpose: ``outcome.runtime_ms`` (a latency measurement, not part of
the decision) and ``health`` (the regime engine's reading over rolling windows
shared with other requests, so process state rather than this output).

The request and the response are the tenant's text, so they are bound as full
SHA-256 hex digests and never copied. Risk ``reasons`` and the style report are
the policy's own words about the decision and are bound as written; a custom
policy should not put request text in them.

Install with: ``pip install -r requirements-cns.txt``.
"""
from __future__ import annotations

import dataclasses
import hashlib
import importlib
from collections.abc import Mapping
from types import ModuleType
from typing import Any, Callable

__all__ = [
    "AUDIT_RECORD_SUBJECT",
    "DECISION_SUBJECT",
    "CnsNotInstalled",
    "audit_record_binds",
    "audit_record_content",
    "audit_record_digest",
    "binds",
    "cns_available",
    "decision_content",
    "decision_digest",
]

INSTALL_HINT = "pip install -r requirements-cns.txt"

DECISION_SUBJECT = "gsa.decision"
AUDIT_RECORD_SUBJECT = "gsa.audit_record"


class CnsNotInstalled(ImportError):
    """Raised by this module's digest functions when ``cns`` cannot be imported."""


def _cns_gate() -> ModuleType:
    """Import ``cns.gate`` on demand, or say exactly what is missing."""
    try:
        return importlib.import_module("cns.gate")
    except ImportError as exc:
        raise CnsNotInstalled(
            "gsa_cns_connector needs the CNS package (cns.gate), which is not "
            f"installed. Install it with: {INSTALL_HINT}. GSA itself works "
            "without it."
        ) from exc


def cns_available() -> bool:
    """Whether the CNS gate contract can be imported in this environment."""
    try:
        _cns_gate()
    except CnsNotInstalled:
        return False
    return True


# ---------------------------------------------------------------- reading a record

def _mapping(obj: object, what: str) -> dict:
    """A dataclass instance or a mapping, as a plain dict (nested dataclasses become dicts)."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.asdict(obj)
    if isinstance(obj, Mapping):
        return dict(obj)
    raise TypeError(f"{what} must be a dataclass instance or a mapping; got {type(obj).__name__}")


def _need(data: dict, keys: tuple, where: str) -> None:
    missing = [where + key for key in keys if key not in data]
    if missing:
        raise ValueError(f"missing required key(s): {', '.join(missing)}")


def _str(value: object, what: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{what} must be a str; got {type(value).__name__}")
    return value


def _int(value: object, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{what} must be an int; got {type(value).__name__}")
    return value


def _num(value: object, what: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{what} must be a number; got {type(value).__name__}")
    return float(value)


def _bool(value: object, what: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{what} must be a bool; got {type(value).__name__}")
    return value


def _hash(value: object, what: str) -> str:
    """Full SHA-256 of a text. Tenant text is bound by this and never copied."""
    # surrogatepass: a client can send a lone surrogate, which must hash rather than raise
    return hashlib.sha256(_str(value, what).encode("utf-8", "surrogatepass")).hexdigest()


def _maybe(read: Callable[[Any, str], Any], value: object, what: str) -> Any:
    return None if value is None else read(value, what)


def _strings(value: object, what: str) -> list:
    if not isinstance(value, (list, tuple)):
        raise TypeError(f"{what} must be a list or tuple; got {type(value).__name__}")
    return [_str(v, f"{what} item") for v in value]


def _plain(value: object, what: str) -> Any:
    """JSON-like content: str, int, float, bool, None, lists and dicts with str keys. Tuples become lists."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (list, tuple)):
        return [_plain(v, what) for v in value]
    if isinstance(value, Mapping):
        if not all(isinstance(k, str) for k in value):
            raise TypeError(f"{what} must have str keys")
        return {k: _plain(v, what) for k, v in value.items()}
    raise TypeError(f"{what} holds a {type(value).__name__}, which cannot be bound")


# ---------------------------------------------------------------- contents

def audit_record_content(record: object) -> dict:
    """The content a verdict on an audit record is bound to."""
    data = _mapping(record, "an audit record")
    _need(data, ("trace_id", "timestamp", "ledger_index", "payload_hash"), "")
    return {
        "trace_id": _str(data["trace_id"], "trace_id"),
        "timestamp": _str(data["timestamp"], "timestamp"),
        "ledger_index": _int(data["ledger_index"], "ledger_index"),
        "payload_hash": _str(data["payload_hash"], "payload_hash"),
        "policy_name": _str(data.get("policy_name", ""), "policy_name"),
        "policy_version": _str(data.get("policy_version", ""), "policy_version"),
    }


def decision_content(trace: object) -> dict:
    """The content a verdict on a gateway decision is bound to.

    ``trace`` is a ``gsa_gateway.TraceBundle`` or its dict form. ``health`` and
    ``outcome.runtime_ms`` are not part of what is bound.
    """
    data = _mapping(trace, "a gateway decision")
    _need(data, ("trace_id", "request_text", "risk", "outcome", "audit"), "")
    risk = _mapping(data["risk"], "risk")
    outcome = _mapping(data["outcome"], "outcome")
    _need(risk, ("blocked", "score", "reasons"), "risk.")
    _need(outcome, ("status", "session_id", "response", "attempts", "style_enforced", "style_report", "telemetry",
                    "attestation"), "outcome.")
    style_report = outcome["style_report"]
    if style_report is not None:
        if not isinstance(style_report, Mapping):
            raise TypeError(f"outcome.style_report must be a mapping or None; got {type(style_report).__name__}")
        style_report = _plain(style_report, "outcome.style_report")
    telemetry = None
    if outcome["telemetry"] is not None:
        raw = _mapping(outcome["telemetry"], "outcome.telemetry")
        _need(raw, ("entropy", "risk_score"), "outcome.telemetry.")
        telemetry = {"entropy": _num(raw["entropy"], "telemetry.entropy"),
                     "risk_score": _num(raw["risk_score"], "telemetry.risk_score")}
    attestation = None
    if outcome["attestation"] is not None:
        raw = _mapping(outcome["attestation"], "outcome.attestation")
        _need(raw, ("forensic_sig", "auth_tag", "signed_at", "nonce"), "outcome.attestation.")
        attestation = {key: _str(raw[key], f"attestation.{key}") for key in ("forensic_sig", "auth_tag", "signed_at", "nonce")}
    return {
        "trace_id": _str(data["trace_id"], "trace_id"),
        "tenant_id": _maybe(_str, data.get("tenant_id"), "tenant_id"),
        "request_sha256": _hash(data["request_text"], "request_text"),
        "risk": {
            "blocked": _bool(risk["blocked"], "risk.blocked"),
            "score": _num(risk["score"], "risk.score"),
            "threshold_used": _maybe(_num, risk.get("threshold_used"), "risk.threshold_used"),
            "hard_block": _bool(risk.get("hard_block", False), "risk.hard_block"),
            "reasons": _strings(risk["reasons"], "risk.reasons"),
            "contributing_members": sorted(_strings(risk.get("contributing_members", []), "risk.contributing_members")),
        },
        "outcome": {
            "status": _int(outcome["status"], "outcome.status"),
            "session_id": _str(outcome["session_id"], "outcome.session_id"),
            "attempts": _int(outcome["attempts"], "outcome.attempts"),
            "style_enforced": _bool(outcome["style_enforced"], "outcome.style_enforced"),
            "response_sha256": None if outcome["response"] is None else _hash(outcome["response"], "outcome.response"),
            "style_report": style_report,
            "telemetry": telemetry,
            "attestation": attestation,
            "note": _str(outcome.get("note", ""), "outcome.note"),
        },
        "audit": audit_record_content(data["audit"]),
    }


# ---------------------------------------------------------------- digests and binding

def decision_digest(trace: object) -> str:
    """The digest a bound verdict on this gateway decision carries."""
    return _cns_gate().subject_digest(decision_content(trace))


def audit_record_digest(record: object) -> str:
    """The digest a bound verdict on this audit record carries."""
    return _cns_gate().subject_digest(audit_record_content(record))


def _binds(result: Any, subject: str, digest: Callable[[], str]) -> bool:
    gate = _cns_gate()
    if not isinstance(result, gate.GateResult):
        raise TypeError(f"binds takes a cns.gate.GateResult; got {type(result).__name__}")
    return result.binds(subject, digest())


def binds(result: Any, trace: object, *, subject: str = DECISION_SUBJECT) -> bool:
    """True iff ``result`` (a ``cns.gate.GateResult``) was issued against exactly this gateway decision.

    A verdict that records nothing it judged (unbound) never binds.
    """
    return _binds(result, subject, lambda: decision_digest(trace))


def audit_record_binds(result: Any, record: object, *, subject: str = AUDIT_RECORD_SUBJECT) -> bool:
    """True iff ``result`` was issued against exactly this audit record."""
    return _binds(result, subject, lambda: audit_record_digest(record))
