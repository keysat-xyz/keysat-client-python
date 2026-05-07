"""Example: verify a Keysat license key offline.

Usage::

    KEYSAT_PUBKEY_PEM=$(cat issuer.pub) python examples/offline_verify.py "LIC1-...-..."

Or set the PEM string inline. The output reports the parsed payload
fields and exits non-zero on bad signature / bad format.
"""

import os
import sys

from keysat_licensing_client import LicensingError, PublicKey, Verifier


def main() -> int:
    pem = os.environ.get("KEYSAT_PUBKEY_PEM")
    if not pem:
        print("error: set KEYSAT_PUBKEY_PEM to the issuer's PEM-encoded public key.", file=sys.stderr)
        return 2
    if len(sys.argv) != 2:
        print("usage: offline_verify.py <license-key>", file=sys.stderr)
        return 2

    verifier = Verifier(PublicKey.from_pem(pem))
    try:
        ok = verifier.verify(sys.argv[1])
    except LicensingError as e:
        print(f"INVALID: {e.kind}: {e}", file=sys.stderr)
        return 1

    print("VALID")
    print(f"  product_id:   {ok.product_id}")
    print(f"  license_id:   {ok.license_id}")
    print(f"  issued_at:    {ok.issued_at}")
    print(f"  expires_at:   {ok.expires_at if ok.expires_at != 0 else 'perpetual'}")
    print(f"  trial:        {ok.is_trial}")
    print(f"  fp_bound:     {ok.is_fingerprint_bound}")
    print(f"  entitlements: {ok.entitlements or '(none)'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
