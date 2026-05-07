"""Machine-fingerprint helper.

The SDK doesn't decide WHAT to use as a fingerprint — that's a product
choice, see PORTING_SDK_TO_NEW_LANGUAGES.md and UPGRADING_EXISTING_SOFTWARE.md
for tradeoffs. The SDK only standardizes how the chosen string is hashed
before being sent to the server (so the server never sees the raw value).
"""

from __future__ import annotations

import hashlib


def hash_fingerprint(raw: str) -> str:
    """SHA-256 the raw fingerprint string and return a hex digest.

    Output is the same as Python's
    `hashlib.sha256(raw.encode()).hexdigest()` — 64 lowercase hex chars.
    Cross-language SDKs all use this exact hashing so a fingerprint
    bound by (say) the TS client validates correctly against the same
    machine's Python client.
    """
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
