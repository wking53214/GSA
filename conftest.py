"""Test-wide setup: the suite runs the gateway in the dev profile, and says so.

An unset GSA_ENV now means prod (see config.py), which refuses the published default key, unsigned tokens and the
in-memory audit log. The tests import gsa_gateway, which builds a demo gateway at import time, so they choose dev
explicitly here, before any test module is imported. An explicit GSA_ENV in the caller's environment is kept.
Tests that check other profiles set GSA_ENV themselves, in Settings(env=...) or in a subprocess environment.
"""
import os

os.environ.setdefault("GSA_ENV", "dev")
