"""Server public key loading and management."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from .errors import LicensingError


class PublicKey:
    """An Ed25519 public key issued by the Keysat server.

    Holds the underlying `cryptography.Ed25519PublicKey` and exposes
    convenience constructors. Pass an instance to `Verifier(...)`.
    """

    def __init__(self, key: Ed25519PublicKey):
        self._key = key

    @classmethod
    def from_pem(cls, pem: str | bytes) -> "PublicKey":
        """Load from a PEM string as returned by the server's `GET /v1/pubkey`.

        Raises `LicensingError(kind="bad_format")` if the PEM is not a
        valid Ed25519 public key.
        """
        if isinstance(pem, str):
            pem = pem.encode("utf-8")
        try:
            loaded = load_pem_public_key(pem)
        except Exception as e:
            raise LicensingError("bad_format", f"could not parse PEM: {e}") from e
        if not isinstance(loaded, Ed25519PublicKey):
            raise LicensingError(
                "bad_format",
                "PEM is not an Ed25519 public key (got "
                f"{type(loaded).__name__})",
            )
        return cls(loaded)

    @classmethod
    def from_raw(cls, raw: bytes) -> "PublicKey":
        """Load from a 32-byte raw Ed25519 public key."""
        if len(raw) != 32:
            raise LicensingError(
                "bad_format",
                f"raw Ed25519 public key must be 32 bytes (got {len(raw)})",
            )
        return cls(Ed25519PublicKey.from_public_bytes(raw))

    @property
    def underlying(self) -> Ed25519PublicKey:
        """Access the underlying cryptography object (for advanced use)."""
        return self._key
