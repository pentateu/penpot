"""ISWE Penpot JWT verifier contract — regression tests.
Mirrors backend/src/app/auth.clj verify-jwt (RS256-only, exact iss/aud, exp required).
No third-party JWT lib: uses stdlib + cryptography (RSA PKCS1v15 + SHA256).

Cases (per plan Phase 2):
1. valid verifies
2. wrong aud rejects
3. unknown email no-profile (verify passes, profile lookup yields nil)
4. expired rejects
5. none/HS256 rejects (alg-confusion)

Run: python3 iswe/test_jwt_verify.py
"""
import base64
import json
import time
import unittest
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ISS = "https://auth.iswe.co.nz/application/o/penpot/"
AUD = "penpot"
LEEWAY = 60

# Mock profile DB (lowercased emails). Unknown email -> no-profile (None).
PROFILES = {"rafael@iswe.co.nz", "agents@iswe.co.nz", "dev1@iswe.co.nz"}


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def mint(payload: dict, key, alg="RS256", kid="test-kid-1") -> str:
    header = {"alg": alg, "typ": "JWT", "kid": kid}
    h = b64u_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64u_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing = f"{h}.{p}".encode()
    if alg == "none":
        return f"{h}.{p}."
    if alg.startswith("HS"):
        import hashlib
        import hmac
        sig = hmac.new(b"fake-secret-for-test", signing, hashlib.sha256).digest()
        return f"{h}.{p}.{b64u_encode(sig)}"
    # RS256
    sig = key.sign(signing, padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{b64u_encode(sig)}"


def verify(token: str, public_key) -> Optional[dict]:
    """Mirror of app.auth/verify-jwt contract. Returns payload or None."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header = json.loads(b64u_decode(parts[0]))
        alg = header.get("alg")
        # RS256-only
        if alg != "RS256":
            return None
        signing = f"{parts[0]}.{parts[1]}".encode()
        sig = b64u_decode(parts[2])
        public_key.verify(sig, signing, padding.PKCS1v15(), hashes.SHA256())
        payload = json.loads(b64u_decode(parts[1]))
        # exact iss
        if payload.get("iss") != ISS:
            return None
        # exact aud: string equal only
        aud = payload.get("aud")
        if not (isinstance(aud, str) and aud == AUD):
            return None
        # exp required
        exp = payload.get("exp")
        if exp is None:
            return None
        now = int(time.time())
        if exp + LEEWAY < now:
            return None
        nbf = payload.get("nbf")
        if nbf is not None and (nbf - LEEWAY) > now:
            return None
        return payload
    except Exception:
        return None


def lookup_profile(email: str):
    """Mirror of session.clj email->profile (case-insensitive). None = no-profile."""
    if not email or "@" not in email:
        return None
    if email.strip().lower() in PROFILES:
        return {"email": email.strip().lower()}
    return None


class TestJwtVerify(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.pub = cls.key.public_key()
        cls.now = int(time.time())

    def base_payload(self, **over):
        p = {
            "iss": ISS,
            "aud": AUD,
            "sub": "rafael@iswe.co.nz",
            "email": "rafael@iswe.co.nz",
            "exp": self.now + 300,
            "iat": self.now,
        }
        p.update(over)
        return p

    def test_valid_verifies(self):
        t = mint(self.base_payload(), self.key)
        payload = verify(t, self.pub)
        self.assertIsNotNone(payload)
        self.assertEqual(payload["email"], "rafael@iswe.co.nz")

    def test_wrong_aud_rejects(self):
        t = mint(self.base_payload(aud="outline"), self.key)
        self.assertIsNone(verify(t, self.pub))
        # array aud also rejects (exact set match)
        t2 = mint(self.base_payload(aud=["penpot"]), self.key)
        self.assertIsNone(verify(t2, self.pub))

    def test_unknown_email_no_profile(self):
        t = mint(self.base_payload(email="ghost@iswe.co.nz", sub="ghost@iswe.co.nz"), self.key)
        payload = verify(t, self.pub)
        # verify passes (sig/iss/aud/exp ok) ...
        self.assertIsNotNone(payload)
        # ... but profile lookup yields nil
        self.assertIsNone(lookup_profile(payload.get("email")))

    def test_expired_rejects(self):
        t = mint(self.base_payload(exp=self.now - 3600), self.key)
        self.assertIsNone(verify(t, self.pub))
        # missing exp rejects
        p = self.base_payload()
        del p["exp"]
        t2 = mint(p, self.key)
        self.assertIsNone(verify(t2, self.pub))

    def test_none_hs256_rejects(self):
        t_none = mint(self.base_payload(), self.key, alg="none")
        self.assertIsNone(verify(t_none, self.pub))
        t_hs = mint(self.base_payload(), self.key, alg="HS256")
        self.assertIsNone(verify(t_hs, self.pub))

    def test_wrong_iss_rejects(self):
        t = mint(self.base_payload(iss="https://auth.iswe.co.nz/application/o/outline/"), self.key)
        self.assertIsNone(verify(t, self.pub))
        # trailing-slash exact: missing slash rejects
        t2 = mint(self.base_payload(iss="https://auth.iswe.co.nz/application/o/penpot"), self.key)
        self.assertIsNone(verify(t2, self.pub))


if __name__ == "__main__":
    unittest.main(verbosity=2)
