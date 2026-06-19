"""Offline signature verification — the bulk of the value of the SDK."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature

from .errors import LicensingError
from .key import LicensePayload, is_expired_at, parse_license_key
from .pubkey import PublicKey


@dataclass(frozen=True)
class VerifyOk:
    """Result of a successful offline `Verifier.verify()` call."""

    license_id: uuid.UUID
    product_id: uuid.UUID
    issued_at: int
    expires_at: int  # 0 = perpetual
    is_trial: bool
    is_fingerprint_bound: bool
    fingerprint_hash: bytes  # 32 bytes; all-zero if unbound
    entitlements: list[str]
    payload: LicensePayload  # the full parsed payload


class Verifier:
    """Offline license-key verifier.

    Given the issuer's PEM-encoded public key, verifies the cryptographic
    integrity of a license key string with no network access. Suitable
    for boot-time license checks where the licensing server may be
    unreachable.

    Usage::

        verifier = Verifier(PublicKey.from_pem(ISSUER_PUBKEY_PEM))
        ok = verifier.verify(key_from_user)
        # raises LicensingError on bad signature / bad format

    For revocation and fingerprint binding, layer the online
    `Client.validate(...)` on top of this — but only AFTER offline
    verification has passed.
    """

    def __init__(self, public_key: PublicKey):
        self._pubkey = public_key

    def verify(self, key: str) -> VerifyOk:
        """Verify a `LIC1-...-...` key.

        On success, returns a `VerifyOk` with all parsed fields. On
        failure, raises `LicensingError`:

          - `kind="bad_format"`: the key string is malformed.
          - `kind="bad_signature"`: signature didn't verify against
            the issuer's public key (key was edited, fabricated, or
            issued by a different server).

        This checks signature and format only, not expiry — call
        `verify_with_time()` to additionally reject expired keys.
        """
        parsed = parse_license_key(key)
        try:
            self._pubkey.underlying.verify(parsed.signature, parsed.payload_bytes)
        except InvalidSignature as e:
            raise LicensingError(
                "bad_signature",
                "signature did not verify against the issuer's public key",
            ) from e
        p = parsed.payload
        return VerifyOk(
            license_id=p.license_id,
            product_id=p.product_id,
            issued_at=p.issued_at,
            expires_at=p.expires_at,
            is_trial=p.is_trial,
            is_fingerprint_bound=p.is_fingerprint_bound,
            fingerprint_hash=p.fingerprint_hash,
            entitlements=list(p.entitlements),
            payload=p,
        )

    def verify_with_time(self, key: str, now_unix: int) -> VerifyOk:
        """Verify a key AND reject it if it has expired at `now_unix`.

        Runs the full `verify()` signature/format check, then raises
        `LicensingError(kind="expired")` if `now_unix` is at or past the
        key's `expires_at`. Perpetual keys (`expires_at == 0`) are
        accepted regardless of `now_unix`. Offline-only — no grace
        window; layer the online `Client.validate(...)` on top for
        revocation/grace. The caller supplies `now_unix` (typically
        `int(time.time())`) so this stays clock-free and testable.
        """
        ok = self.verify(key)
        if is_expired_at(ok.payload, now_unix):
            raise LicensingError("expired", "license has expired")
        return ok
