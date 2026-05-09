"""
keysat_licensing_client
=======================

Python client for Keysat — a self-hosted Bitcoin-paid software licensing
server that runs on Start9. Verifies signed license keys offline, and
(via the optional `online` extra) wraps the HTTP API for purchase,
free-license redemption, and revocation checks.

Five-line offline check::

    from keysat_licensing_client import Verifier, PublicKey

    verifier = Verifier(PublicKey.from_pem(ISSUER_PUBKEY_PEM))
    ok = verifier.verify(key_from_user)
    print("licensed for product", ok.product_id)

Online client (requires the `online` extra: `pip install keysat-licensing-client[online]`)::

    from keysat_licensing_client import Client
    client = Client("https://license.example.com")
    r = client.validate(key_from_user, product_slug="my-product",
                        fingerprint=machine_fingerprint)
    if not r.ok:
        ...
"""

from .errors import LicensingError
from .key import (
    FLAG_FINGERPRINT_BOUND,
    FLAG_TRIAL,
    KEY_PREFIX,
    KEY_VERSION_V1,
    KEY_VERSION_V2,
    LicensePayload,
    has_entitlement,
    is_expired_at,
    parse_license_key,
)
from .pubkey import PublicKey
from .verify import VerifyOk, Verifier
from .fingerprint import hash_fingerprint

__all__ = [
    "LicensingError",
    "PublicKey",
    "Verifier",
    "VerifyOk",
    "LicensePayload",
    "parse_license_key",
    "is_expired_at",
    "has_entitlement",
    "hash_fingerprint",
    "FLAG_FINGERPRINT_BOUND",
    "FLAG_TRIAL",
    "KEY_PREFIX",
    "KEY_VERSION_V1",
    "KEY_VERSION_V2",
]

# Online client is gated on optional dependency `httpx`. We try to
# expose it but degrade silently if httpx isn't installed — the offline
# verifier (above) doesn't need network at all.
try:
    from .online import (  # noqa: F401
        Client,
        ValidateResponse,
        ValidateOptions,
        StartPurchaseOptions,
        PublicPolicy,
        PublicPoliciesProduct,
        PublicPoliciesResponse,
        PurchaseSession,
        PollResponse,
        RedeemFreeOptions,
        RedeemFreeResponse,
    )

    __all__ += [
        "Client",
        "ValidateResponse",
        "ValidateOptions",
        "StartPurchaseOptions",
        "PublicPolicy",
        "PublicPoliciesProduct",
        "PublicPoliciesResponse",
        "PurchaseSession",
        "PollResponse",
        "RedeemFreeOptions",
        "RedeemFreeResponse",
    ]
except ImportError:
    # httpx not installed — that's fine, online client is optional.
    pass

__version__ = "0.2.0"
