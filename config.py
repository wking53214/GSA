"""
config.py — 12-factor configuration for the GSA gateway
=======================================================
Operational knobs come from the environment (with safe defaults), not hard-coded
constants. This is what lets the same image run in dev / staging / prod by config
alone. A .env file (see .env.example) or real env vars both work.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    # --- service ---
    env: str = field(default_factory=lambda: _env("GSA_ENV", "dev"))
    log_level: str = field(default_factory=lambda: _env("GSA_LOG_LEVEL", "INFO"))

    # --- request limits ---
    max_request_chars: int = field(default_factory=lambda: _env_int("GSA_MAX_REQUEST_CHARS", 8000))

    # --- input risk threshold / FDR control ---
    risk_block_threshold: float = field(default_factory=lambda: _env_float("GSA_RISK_BLOCK_THRESHOLD", 0.80))
    fdr_target: float = field(default_factory=lambda: _env_float("GSA_FDR_TARGET", 0.05))

    # --- correction loop / attestation pool ---
    max_correction_attempts: int = field(default_factory=lambda: _env_int("GSA_MAX_CORRECTION_ATTEMPTS", 4))
    attestation_workers: int = field(default_factory=lambda: _env_int("GSA_ATTESTATION_WORKERS", 4))
    attestation_queue_size: int = field(default_factory=lambda: _env_int("GSA_ATTESTATION_QUEUE_SIZE", 256))

    # --- circuit breaker ---
    cb_failure_threshold: int = field(default_factory=lambda: _env_int("GSA_CB_FAILURE_THRESHOLD", 5))
    cb_recovery_timeout_s: float = field(default_factory=lambda: _env_float("GSA_CB_RECOVERY_TIMEOUT_S", 5.0))

    # --- rate limiting ---
    rate_limit_capacity: int = field(default_factory=lambda: _env_int("GSA_RATE_LIMIT_CAPACITY", 60))
    rate_limit_refill_per_sec: float = field(default_factory=lambda: _env_float("GSA_RATE_LIMIT_REFILL_PER_SEC", 10.0))

    # --- secrets / auth ---
    secret_provider: str = field(default_factory=lambda: _env("GSA_SECRET_PROVIDER", "env"))  # env|file
    hmac_secret_env: str = field(default_factory=lambda: _env("GSA_SECRET_KEY", ""))
    # JWT: when a public key is configured, bearer tokens are verified as RS256 JWTs.
    jwt_public_key_path: str = field(default_factory=lambda: _env("GSA_JWT_PUBLIC_KEY_PATH", ""))
    jwt_issuer: str = field(default_factory=lambda: _env("GSA_JWT_ISSUER", ""))
    jwt_audience: str = field(default_factory=lambda: _env("GSA_JWT_AUDIENCE", ""))
    jwt_tenant_claim: str = field(default_factory=lambda: _env("GSA_JWT_TENANT_CLAIM", "tenant_id"))

    # --- persistence ---
    # audit_backend: memory | sqlite (anything else is rejected). prod requires sqlite.
    audit_backend: str = field(default_factory=lambda: _env("GSA_AUDIT_BACKEND", "memory"))
    audit_db_path: str = field(default_factory=lambda: _env("GSA_AUDIT_DB_PATH", "gsa_audit.db"))

    def summary(self) -> dict:
        redacted = "<set>" if self.hmac_secret_env else "<unset>"
        return {
            "env": self.env, "audit_backend": self.audit_backend,
            "secret_provider": self.secret_provider, "hmac_secret": redacted,
            "jwt": "RS256" if self.jwt_public_key_path else "bearer-dev",
            "rate_limit": f"{self.rate_limit_capacity}/{self.rate_limit_refill_per_sec}s",
        }


# module-level singleton (read once at import; override in tests by constructing Settings())
settings = Settings()


if __name__ == "__main__":
    print("GSA settings:", Settings().summary())
