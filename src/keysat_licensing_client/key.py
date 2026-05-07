"""License key payload struct and parser.

Wire format reference: see PORTING_SDK_TO_NEW_LANGUAGES.md and
licensing-service/src/crypto/mod.rs. Both v1 (legacy fixed-74) and v2
(variable-length with expires_at + entitlements) layouts are supported.

Format summary::

    LIC1-<base32(payload)>-<base32(signature)>

    base32: RFC 4648, uppercase, no padding.
    signature: 64 bytes Ed25519 over the raw payload bytes.

    v1 payload (74 bytes, fixed):
      [0]      version (=1)
      [1]      flags (bit 0 FINGERPRINT_BOUND, bit 1 TRIAL)
      [2..18]  product_id (UUID big-endian)
      [18..34] license_id (UUID big-endian)
      [34..42] issued_at (u64 big-endian, unix seconds)
      [42..74] fingerprint_hash (SHA-256 hex digest, 32 raw bytes)

    v2 payload (83+ bytes):
      [0]      version (=2)
      [1]      flags
      [2..18]  product_id
      [18..34] license_id
      [34..42] issued_at (u64 big-endian)
      [42..50] expires_at (u64 big-endian; 0 = perpetual)
      [50..82] fingerprint_hash
      [82]     num_entitlements (u8)
      [83..]   for each: <u8 len><len bytes UTF-8 entitlement slug>
"""

from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass, field

from .errors import LicensingError

KEY_PREFIX = "LIC1"
KEY_VERSION_V1 = 1
KEY_VERSION_V2 = 2

FLAG_FINGERPRINT_BOUND = 0b0000_0001
FLAG_TRIAL = 0b0000_0010

V1_LEN = 74
V2_HEAD_LEN = 83  # bytes 0..82 fixed, then variable entitlement tail


@dataclass(frozen=True)
class LicensePayload:
    """Decoded license payload. Returned by `parse_license_key()`."""

    version: int
    flags: int
    product_id: uuid.UUID
    license_id: uuid.UUID
    issued_at: int  # unix seconds
    expires_at: int  # unix seconds; 0 = perpetual; v1 keys always 0
    fingerprint_hash: bytes  # 32 bytes; all-zero if unbound
    entitlements: list[str] = field(default_factory=list)

    @property
    def is_fingerprint_bound(self) -> bool:
        return bool(self.flags & FLAG_FINGERPRINT_BOUND)

    @property
    def is_trial(self) -> bool:
        return bool(self.flags & FLAG_TRIAL)


@dataclass(frozen=True)
class ParsedKey:
    """Parsed (but NOT signature-verified) license key.

    Carries the payload and the raw payload bytes (needed for signature
    verification — the signature is over the bytes, not the parsed
    struct).
    """

    payload: LicensePayload
    payload_bytes: bytes
    signature: bytes  # 64 bytes


def _b32_decode_nopad(s: str) -> bytes:
    """Decode RFC4648 base32, uppercase, with no padding. Adds padding
    if needed to satisfy stdlib's strict decoder."""
    s = s.upper()
    pad = (-len(s)) % 8
    return base64.b32decode(s + "=" * pad)


def parse_license_key(key: str) -> ParsedKey:
    """Parse a `LIC1-<payload>-<sig>` key string. Does NOT verify the
    signature — use `Verifier.verify()` for that.

    Raises `LicensingError(kind="bad_format")` on malformed input.
    """
    if not isinstance(key, str):
        raise LicensingError("bad_format", "key must be a string")
    parts = key.strip().split("-")
    if len(parts) != 3:
        raise LicensingError(
            "bad_format",
            f"expected `LIC1-<payload>-<sig>`, got {len(parts)} dash-separated parts",
        )
    prefix, payload_b32, sig_b32 = parts
    if prefix != KEY_PREFIX:
        raise LicensingError("bad_format", f"unknown prefix '{prefix}'; expected '{KEY_PREFIX}'")

    try:
        payload_bytes = _b32_decode_nopad(payload_b32)
        signature = _b32_decode_nopad(sig_b32)
    except Exception as e:
        raise LicensingError("bad_format", f"base32 decode failed: {e}") from e

    if len(signature) != 64:
        raise LicensingError(
            "bad_format",
            f"signature must be 64 bytes (got {len(signature)})",
        )

    return ParsedKey(
        payload=_decode_payload(payload_bytes),
        payload_bytes=payload_bytes,
        signature=signature,
    )


def _decode_payload(payload: bytes) -> LicensePayload:
    if len(payload) < 2:
        raise LicensingError("bad_format", "payload too short")
    version = payload[0]
    flags = payload[1]
    if version == KEY_VERSION_V1:
        if len(payload) != V1_LEN:
            raise LicensingError(
                "bad_format",
                f"v1 payload must be exactly {V1_LEN} bytes (got {len(payload)})",
            )
        product_id = uuid.UUID(bytes=payload[2:18])
        license_id = uuid.UUID(bytes=payload[18:34])
        issued_at = int.from_bytes(payload[34:42], "big")
        fingerprint_hash = payload[42:74]
        return LicensePayload(
            version=version,
            flags=flags,
            product_id=product_id,
            license_id=license_id,
            issued_at=issued_at,
            expires_at=0,  # v1 has no expiry
            fingerprint_hash=fingerprint_hash,
            entitlements=[],
        )
    elif version == KEY_VERSION_V2:
        if len(payload) < V2_HEAD_LEN:
            raise LicensingError(
                "bad_format",
                f"v2 payload header is {V2_HEAD_LEN} bytes; got {len(payload)}",
            )
        product_id = uuid.UUID(bytes=payload[2:18])
        license_id = uuid.UUID(bytes=payload[18:34])
        issued_at = int.from_bytes(payload[34:42], "big")
        expires_at = int.from_bytes(payload[42:50], "big")
        fingerprint_hash = payload[50:82]
        num_ents = payload[82]
        entitlements: list[str] = []
        cursor = 83
        for _ in range(num_ents):
            if cursor >= len(payload):
                raise LicensingError("bad_format", "v2 entitlement length byte missing")
            slen = payload[cursor]
            cursor += 1
            if cursor + slen > len(payload):
                raise LicensingError("bad_format", "v2 entitlement extends past payload")
            slug = payload[cursor : cursor + slen].decode("utf-8")
            cursor += slen
            entitlements.append(slug)
        if cursor != len(payload):
            raise LicensingError(
                "bad_format",
                f"v2 payload has {len(payload) - cursor} trailing bytes after entitlements",
            )
        return LicensePayload(
            version=version,
            flags=flags,
            product_id=product_id,
            license_id=license_id,
            issued_at=issued_at,
            expires_at=expires_at,
            fingerprint_hash=fingerprint_hash,
            entitlements=entitlements,
        )
    else:
        raise LicensingError("bad_format", f"unknown key version: {version}")


def is_expired_at(payload: LicensePayload, when_unix: int) -> bool:
    """Pure helper: is this key expired AT a given unix timestamp?

    Returns False for perpetual keys (expires_at == 0) regardless of
    when. Caller supplies `when_unix` so this is a pure function — no
    clock dependency. Typically the caller passes `int(time.time())`.
    """
    if payload.expires_at == 0:
        return False
    return when_unix >= payload.expires_at


def has_entitlement(payload: LicensePayload, slug: str) -> bool:
    """Does the license grant the given entitlement slug?"""
    return slug in payload.entitlements
