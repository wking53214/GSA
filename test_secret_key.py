"""The attestation signing key is the one that was configured, and a default key is never used outside dev.

Found by running it: with GSA_SECRET_KEY set to a real secret, attestations were still signed with the published
development key. config.py stored the secret's VALUE where gsa_gateway.py passed it on as the NAME of an environment
variable, so the lookup found nothing and fell back to the default key; and nothing refused that fallback in prod. The
README, RUNBOOK and k8s files all say the key is required, so every real deployment set it and had it ignored.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest

import gsa_gateway
from auth import EnvSecretProvider, FileSecretProvider, MissingSecretError
from config import Settings

DEV_KEY = b"dev-only-insecure-key-change-me"
SECRET = "a-real-production-secret-value"
ROOT = Path(__file__).resolve().parent


def _settings(monkeypatch, **env) -> Settings:
    for name in list(os.environ):
        if name.startswith("GSA_"):
            monkeypatch.delenv(name)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    return Settings()


def _key(settings: Settings) -> bytes:
    return gsa_gateway._build_secret_provider(settings).get_hmac_key()


def test_the_configured_secret_is_the_key_that_is_used(monkeypatch):
    assert _key(_settings(monkeypatch, GSA_SECRET_KEY=SECRET)) == SECRET.encode()


def test_the_settings_field_holds_a_variable_name_not_the_secret(monkeypatch):
    settings = _settings(monkeypatch, GSA_SECRET_KEY=SECRET)
    assert settings.hmac_secret_env == "GSA_SECRET_KEY" and SECRET not in repr(settings)


def test_a_differently_named_variable_can_be_configured(monkeypatch):
    monkeypatch.setenv("MY_SIGNING_KEY", "from-another-variable")
    settings = Settings(hmac_secret_env="MY_SIGNING_KEY", env="prod")
    assert _key(settings) == b"from-another-variable"


@pytest.mark.parametrize("profile", ["prod", "staging", "production", "test", ""])
def test_no_profile_but_dev_accepts_the_default_key(monkeypatch, profile):
    settings = Settings(env=profile)
    monkeypatch.delenv("GSA_SECRET_KEY", raising=False)
    with pytest.raises(MissingSecretError, match="GSA_SECRET_KEY is not set"):
        _key(settings)


@pytest.mark.parametrize("profile", ["prod", "staging"])
def test_a_secret_works_in_every_profile(monkeypatch, profile):
    monkeypatch.setenv("GSA_SECRET_KEY", SECRET)
    assert _key(Settings(env=profile)) == SECRET.encode() != DEV_KEY


def test_dev_may_use_the_default_key_and_says_so(monkeypatch, caplog):
    monkeypatch.delenv("GSA_SECRET_KEY", raising=False)
    with caplog.at_level("WARNING"):
        assert _key(Settings(env="dev")) == DEV_KEY
    assert "insecure development key" in caplog.text


def test_an_empty_variable_is_a_missing_key(monkeypatch):
    monkeypatch.setenv("GSA_SECRET_KEY", "")
    with pytest.raises(MissingSecretError):
        _key(Settings(env="prod"))


def test_the_provider_refuses_a_default_key_unless_told_otherwise(monkeypatch):
    monkeypatch.delenv("GSA_SECRET_KEY", raising=False)
    with pytest.raises(MissingSecretError):
        EnvSecretProvider().get_hmac_key()
    assert EnvSecretProvider(allow_dev_key=True).get_hmac_key() == DEV_KEY


def test_the_refusal_never_contains_the_secret(monkeypatch):
    monkeypatch.setenv("GSA_SECRET_KEY", "")
    with pytest.raises(MissingSecretError) as info:
        EnvSecretProvider(hmac_env="GSA_SECRET_KEY").get_hmac_key()
    assert SECRET not in str(info.value)


def test_a_key_file_is_used_and_an_empty_one_is_refused(tmp_path):
    good = tmp_path / "key"
    good.write_bytes(b"  from-a-file\n")
    assert FileSecretProvider(str(good)).get_hmac_key() == b"from-a-file"
    for content in (b"", b"   \n"):
        empty = tmp_path / "empty"
        empty.write_bytes(content)
        with pytest.raises(MissingSecretError, match="is empty"):
            FileSecretProvider(str(empty)).get_hmac_key()


def test_the_settings_summary_reports_set_or_unset_and_never_the_secret(monkeypatch):
    shown = _settings(monkeypatch, GSA_SECRET_KEY=SECRET).summary()
    assert shown["hmac_secret"] == "<set>" and SECRET not in str(shown)
    assert _settings(monkeypatch).summary()["hmac_secret"] == "<unset>"


def _import_gateway(tmp_path, **env):
    """Import the module in a fresh interpreter, which builds the app and therefore reads the key at startup."""
    clean = {k: v for k, v in os.environ.items() if not k.startswith("GSA_")}
    clean.update(GSA_AUDIT_DB_PATH=str(tmp_path / "audit.db"), **env)
    # The expected secret is read from the child's environment, not written into the command, so a traceback that
    # echoes the command cannot make "the secret never appears in the output" fail for the wrong reason.
    code = ("import os, gsa_gateway as g; "
            "print(g._load_secret() == os.environ.get('GSA_SECRET_KEY', '').encode())")
    return subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=clean, capture_output=True, text=True, timeout=120)


def test_the_service_refuses_to_start_in_prod_without_a_key(tmp_path):
    done = _import_gateway(tmp_path, GSA_ENV="prod", GSA_AUDIT_BACKEND="sqlite")
    assert done.returncode != 0 and "MissingSecretError" in done.stderr


def test_the_service_starts_in_prod_with_a_key_and_signs_with_it(tmp_path):
    done = _import_gateway(tmp_path, GSA_ENV="prod", GSA_AUDIT_BACKEND="sqlite", GSA_SECRET_KEY=SECRET)
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "True"
    assert SECRET not in done.stderr
