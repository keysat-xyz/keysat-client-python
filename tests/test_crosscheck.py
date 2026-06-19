"""Cross-check the Python SDK against the canonical wire-format test
vectors at ../../tests/crosscheck/vector.json.

These vectors are also exercised by the Rust and TS SDKs. Any new SDK
must pass every fixture in vector.json — that's how we guarantee
wire-format compatibility across languages.

Run with: `pytest -q` from the package root, OR `python -m pytest`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from keysat_licensing_client import (
    PublicKey,
    Verifier,
    LicensingError,
    has_entitlement,
    hash_fingerprint,
    is_expired_at,
    parse_license_key,
)


# Locate vector.json relative to this file. The tests directory lives
# at licensing-client-python/tests/, the vector lives at
# tests/crosscheck/vector.json (repo root). Walk up until we find it.
def _vectors_path() -> Path:
    here = Path(__file__).resolve().parent
    for ancestor in [here, *here.parents]:
        candidate = ancestor / "tests" / "crosscheck" / "vector.json"
        if candidate.exists():
            return candidate
    pytest.skip("crosscheck vector.json not found; run from repo with tests/ tree")


@pytest.fixture(scope="module")
def vectors() -> dict:
    with _vectors_path().open() as f:
        return json.load(f)


@pytest.fixture(scope="module")
def verifier(vectors: dict) -> Verifier:
    return Verifier(PublicKey.from_pem(vectors["publicKeyPem"]))


# ------------------------------------------------------------------
# v1 fixture: legacy fixed-74 layout, fingerprint-bound, no expiry,
# no entitlements.
# ------------------------------------------------------------------


def test_v1_parses(vectors: dict) -> None:
    parsed = parse_license_key(vectors["v1"]["licenseKey"])
    exp = vectors["v1"]["expected"]
    assert parsed.payload.version == exp["version"]
    assert str(parsed.payload.product_id) == exp["productUuid"]
    assert str(parsed.payload.license_id) == exp["licenseUuid"]
    assert parsed.payload.issued_at == exp["issuedAt"]
    assert parsed.payload.expires_at == exp["expiresAt"]
    assert parsed.payload.flags == exp["flags"]
    assert parsed.payload.is_fingerprint_bound is exp["isFingerprintBound"]
    assert parsed.payload.is_trial is exp["isTrial"]
    assert parsed.payload.entitlements == exp["entitlements"]
    assert parsed.payload.fingerprint_hash.hex() == exp["fingerprintHashHex"]


def test_v1_verifies(verifier: Verifier, vectors: dict) -> None:
    ok = verifier.verify(vectors["v1"]["licenseKey"])
    assert str(ok.product_id) == vectors["v1"]["expected"]["productUuid"]


def test_v1_tamper_detected(verifier: Verifier, vectors: dict) -> None:
    key = vectors["v1"]["licenseKey"]
    # Flip one char in the payload section. The signature won't match.
    payload_start = key.index("-") + 1
    tampered = key[:payload_start] + ("B" if key[payload_start] != "B" else "C") + key[payload_start + 1 :]
    with pytest.raises(LicensingError) as excinfo:
        verifier.verify(tampered)
    assert excinfo.value.kind in ("bad_signature", "bad_format")


# ------------------------------------------------------------------
# v2 fixture: trial, fingerprint-bound, explicit expiry, two entitlements.
# Stresses the variable-length tail parser.
# ------------------------------------------------------------------


def test_v2_parses(vectors: dict) -> None:
    parsed = parse_license_key(vectors["v2"]["licenseKey"])
    exp = vectors["v2"]["expected"]
    assert parsed.payload.version == exp["version"]
    assert str(parsed.payload.product_id) == exp["productUuid"]
    assert str(parsed.payload.license_id) == exp["licenseUuid"]
    assert parsed.payload.issued_at == exp["issuedAt"]
    assert parsed.payload.expires_at == exp["expiresAt"]
    assert parsed.payload.flags == exp["flags"]
    assert parsed.payload.is_fingerprint_bound is exp["isFingerprintBound"]
    assert parsed.payload.is_trial is exp["isTrial"]
    assert parsed.payload.entitlements == exp["entitlements"]


def test_v2_verifies(verifier: Verifier, vectors: dict) -> None:
    ok = verifier.verify(vectors["v2"]["licenseKey"])
    assert ok.is_trial
    assert ok.is_fingerprint_bound
    assert len(ok.entitlements) == len(vectors["v2"]["expected"]["entitlements"])


def test_v2_expiry_boundary(vectors: dict) -> None:
    parsed = parse_license_key(vectors["v2"]["licenseKey"])
    expires_at = parsed.payload.expires_at
    assert is_expired_at(parsed.payload, expires_at) is True
    assert is_expired_at(parsed.payload, expires_at - 1) is False


def test_v2_verify_with_time_rejects_expired(verifier: Verifier, vectors: dict) -> None:
    key = vectors["v2"]["licenseKey"]
    expires_at = vectors["v2"]["expected"]["expiresAt"]
    # At/after expiry the signed-but-expired key must be rejected...
    with pytest.raises(LicensingError) as excinfo:
        verifier.verify_with_time(key, expires_at)
    assert excinfo.value.kind == "expired"
    # ...but one second earlier it's still valid.
    ok = verifier.verify_with_time(key, expires_at - 1)
    assert str(ok.product_id) == vectors["v2"]["expected"]["productUuid"]


def test_v2_entitlements(vectors: dict) -> None:
    parsed = parse_license_key(vectors["v2"]["licenseKey"])
    for slug in vectors["v2"]["expected"]["entitlements"]:
        assert has_entitlement(parsed.payload, slug)
    assert has_entitlement(parsed.payload, "definitely-not-a-real-entitlement") is False


# ------------------------------------------------------------------
# v2_perpetual_unbound — common case for paid purchase: v2, no expiry,
# no fingerprint binding, no entitlements.
# ------------------------------------------------------------------


def test_v2_perpetual_unbound_parses(vectors: dict) -> None:
    if "v2_perpetual_unbound" not in vectors:
        pytest.skip("vector.json doesn't include v2_perpetual_unbound")
    parsed = parse_license_key(vectors["v2_perpetual_unbound"]["licenseKey"])
    assert parsed.payload.version == 2
    assert parsed.payload.expires_at == 0
    assert parsed.payload.is_fingerprint_bound is False


def test_v2_perpetual_unbound_verifies(verifier: Verifier, vectors: dict) -> None:
    if "v2_perpetual_unbound" not in vectors:
        pytest.skip("vector.json doesn't include v2_perpetual_unbound")
    verifier.verify(vectors["v2_perpetual_unbound"]["licenseKey"])


def test_v2_perpetual_verify_with_time_never_expires(verifier: Verifier, vectors: dict) -> None:
    if "v2_perpetual_unbound" not in vectors:
        pytest.skip("vector.json doesn't include v2_perpetual_unbound")
    # A perpetual key (expires_at == 0) is accepted even far in the future.
    ok = verifier.verify_with_time(vectors["v2_perpetual_unbound"]["licenseKey"], 4_000_000_000)
    assert ok.expires_at == 0


# ------------------------------------------------------------------
# Cross-language fingerprint-hash compatibility.
# ------------------------------------------------------------------


def test_hash_fingerprint_matches_python_stdlib() -> None:
    import hashlib
    raw = "hello"
    expected = hashlib.sha256(raw.encode()).hexdigest()
    assert hash_fingerprint(raw) == expected


# ------------------------------------------------------------------
# Negative cases.
# ------------------------------------------------------------------


def test_bad_format_short_key() -> None:
    with pytest.raises(LicensingError) as excinfo:
        parse_license_key("notakey")
    assert excinfo.value.kind == "bad_format"


def test_bad_format_wrong_prefix() -> None:
    with pytest.raises(LicensingError) as excinfo:
        parse_license_key("LIC9-AAAA-BBBB")
    assert excinfo.value.kind == "bad_format"
