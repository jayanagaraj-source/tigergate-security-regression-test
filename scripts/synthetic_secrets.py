"""Every secret-shaped value in the fixtures, regenerated from its seed.

Each value is derived from sha256("tigergate-regression:<seed>"), so anyone can reproduce it and confirm it
was never a credential. scripts/check-repo.sh runs the secret engine over the repository and fails when a
detected value is not one of these, or when a detection falls outside the secret fixture paths.
"""
import base64
import hashlib
import json

ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
BASE62_SEEDS = ["SEC-TP-001", "SEC-TP-002", "SEC-TP-003", "SEC-DUP-002a", "SEC-DUP-002b", "SEC-DUP-003a",
                "SEC-DUP-003b", "SEC-DUP-004", "SEC-DUP-005", "SEC-DUP-006a", "SEC-DUP-006b", "SEC-DUP-006c",
                "SEC-EDGE-001", "SEC-EDGE-002", "SEC-LOC-001"]
AWS_KEY_ID_SEEDS = ["SEC-AWS-1", "SEC-AWS-2", "SEC-AWS-3"]
HEX40_SEEDS = ["eth", "gcpkid", "gcpkid-template"]

# Where a secret engine may legitimately report something.
ALLOWED_PREFIXES = ("cases/secrets/", "loc/minified/analytics.min.js")


def digest(seed):
    return hashlib.sha256(("tigergate-regression:" + seed).encode()).digest()


def base62(seed, n):
    x = int.from_bytes(digest(seed) + digest(seed + "2"), "big")
    out = ""
    while len(out) < n:
        out += ALPHABET[x % 62]
        x //= 62
    return out


def jwt():
    enc = lambda obj: base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")
    return enc({"alg": "HS256", "typ": "JWT"}) + "." + enc({"sub": "tigergate-regression-fixture", "iat": 1700000000}) + \
        "." + base62("SEC-JWTSIG", 43)


def pem_body():
    return base64.b64encode(b"".join(digest("pem%d" % i) for i in range(24))).decode()


def values():
    out = {base62(s, 32) for s in BASE62_SEEDS}
    out |= {"AKIA" + base64.b32encode(digest(s)).decode()[:16] for s in AWS_KEY_ID_SEEDS}
    out |= {digest(s).hex()[:40] for s in HEX40_SEEDS}
    out.add("0x" + digest("eth").hex()[:40])
    out.add(jwt())
    return out


def is_synthetic(secret):
    """True when secret is a derived value, or a PEM block whose body is the derived PEM body (or its prefix)."""
    s = secret.strip().strip("\"'")
    if s in values():
        return True
    if "PRIVATE KEY" in s:
        body = "".join(l for l in s.replace("\\n", "\n").splitlines() if l and "-----" not in l)
        return bool(body) and pem_body().startswith(body)
    return False
