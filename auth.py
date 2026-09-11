"""
auth.py — secret management + token verification
================================================
Two readiness gaps closed:

  1. Secret management. Secrets load through a SecretProvider interface rather than
     being read inline from os.environ at one call site. EnvSecretProvider and
     FileSecretProvider ship; a Vault/KMS provider implements the same two methods.

  2. Real token verification. When a public key is configured, bearer tokens are
     verified as RS256 JWTs — signature, expiry, issuer, and audience are all
     checked, and the tenant id comes from a signed claim (not from hashing an
     opaque string). With no public key, a clearly-labelled DEV fallback remains so
     local runs work without an IdP.

This module imports nothing from the gateway.
"""
from __future__ import annotations

import hashlib
import logging
import os
from abc import ABC, abstractmethod
from typing import Optional

import jwt  # PyJWT

logger = logging.getLogger("GSA_AUTH")


class AuthError(Exception):
    pass


# ---------------------------------------------------------------------------
# Secret providers
# ---------------------------------------------------------------------------
class SecretProvider(ABC):
    @abstractmethod
    def get_hmac_key(self) -> bytes: ...
    def get_jwt_public_key(self) -> Optional[str]:
        return None


class EnvSecretProvider(SecretProvider):
    def __init__(self, hmac_env: str = "GSA_SECRET_KEY", jwt_public_key_path: str = "") -> None:
        self._hmac_env = hmac_env
        self._jwt_path = jwt_public_key_path

    def get_hmac_key(self) -> bytes:
        v = os.environ.get(self._hmac_env, "")
        if v:
            return v.encode("utf-8")
        logger.warning("HMAC secret not set — using an insecure development key. Do not run this in production.")
        return b"dev-only-insecure-key-change-me"

    def get_jwt_public_key(self) -> Optional[str]:
        if self._jwt_path and os.path.exists(self._jwt_path):
            with open(self._jwt_path, "r") as fh:
                return fh.read()
        return None


class FileSecretProvider(SecretProvider):
    """Reads the HMAC key from a mounted secret file (e.g. a k8s Secret volume).
    The same shape a Vault/KMS provider would take."""
    def __init__(self, hmac_path: str, jwt_public_key_path: str = "") -> None:
        self._hmac_path = hmac_path
        self._jwt_path = jwt_public_key_path

    def get_hmac_key(self) -> bytes:
        with open(self._hmac_path, "rb") as fh:
            return fh.read().strip()

    def get_jwt_public_key(self) -> Optional[str]:
        if self._jwt_path and os.path.exists(self._jwt_path):
            with open(self._jwt_path, "r") as fh:
                return fh.read()
        return None


# ---------------------------------------------------------------------------
# Tenant authentication
# ---------------------------------------------------------------------------
class TenantAuthenticator:
    """Resolves a bearer token to a tenant id. RS256 JWT when a public key is
    present; a labelled dev fallback otherwise."""
    def __init__(self, public_key_pem: Optional[str] = None, issuer: str = "",
                 audience: str = "", tenant_claim: str = "tenant_id",
                 allow_dev_fallback: bool = True) -> None:
        self.public_key_pem = public_key_pem
        self.issuer = issuer
        self.audience = audience
        self.tenant_claim = tenant_claim
        self.allow_dev_fallback = allow_dev_fallback

    @property
    def mode(self) -> str:
        return "RS256" if self.public_key_pem else "dev-bearer"

    def authenticate(self, token: str) -> str:
        if not token:
            raise AuthError("missing token")

        if self.public_key_pem:
            options = {"require": ["exp"]}
            kwargs = {"algorithms": ["RS256"], "options": options}
            if self.audience:
                kwargs["audience"] = self.audience
            if self.issuer:
                kwargs["issuer"] = self.issuer
            try:
                claims = jwt.decode(token, self.public_key_pem, **kwargs)
            except jwt.ExpiredSignatureError as e:
                raise AuthError("token expired") from e
            except jwt.InvalidTokenError as e:
                raise AuthError(f"invalid token: {e}") from e
            tenant = claims.get(self.tenant_claim)
            if not tenant:
                raise AuthError(f"token missing '{self.tenant_claim}' claim")
            return str(tenant)

        # dev fallback (no IdP configured)
        if not self.allow_dev_fallback:
            raise AuthError("JWT verification required but no public key configured")
        if len(token) < 12:
            raise AuthError("invalid dev token")
        return f"tenant_{hashlib.sha256(token.encode()).hexdigest()[:8].upper()}"


if __name__ == "__main__":
    import datetime
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = key.private_bytes(serialization.Encoding.PEM,
                                 serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption())
    pub_pem = key.public_key().public_bytes(serialization.Encoding.PEM,
                                             serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    auth = TenantAuthenticator(public_key_pem=pub_pem, issuer="gsa-idp",
                               audience="gsa-gateway", tenant_claim="tenant_id")
    now = datetime.datetime.now(datetime.timezone.utc)
    good = jwt.encode({"tenant_id": "acme-corp", "iss": "gsa-idp", "aud": "gsa-gateway",
                       "exp": now + datetime.timedelta(minutes=5)}, priv_pem, algorithm="RS256")
    print("valid token -> tenant:", auth.authenticate(good))

    expired = jwt.encode({"tenant_id": "x", "iss": "gsa-idp", "aud": "gsa-gateway",
                          "exp": now - datetime.timedelta(minutes=5)}, priv_pem, algorithm="RS256")
    for label, tok in [("expired", expired), ("tampered", good[:-3] + "AAA"),
                       ("wrong-aud", jwt.encode({"tenant_id": "x", "iss": "gsa-idp", "aud": "other",
                                                 "exp": now + datetime.timedelta(minutes=5)}, priv_pem, algorithm="RS256"))]:
        try:
            auth.authenticate(tok)
            print(f"{label}: ACCEPTED (BUG)")
        except AuthError as e:
            print(f"{label}: rejected ({e})")
