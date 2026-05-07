"""Exception types for keysat_licensing_client."""


class LicensingError(Exception):
    """Base exception for all keysat_licensing_client errors.

    Subclasses (or `kind` strings on the base class) distinguish
    specific failure modes:

      - `bad_signature`: the key's Ed25519 signature didn't verify.
      - `bad_format`:    the key string isn't a parseable LIC1-... key.
      - `expired`:       the key parsed and verified but is past its expiry.
      - `revoked`:       the server reported the key as revoked.
      - `fingerprint_mismatch`: the key was bound to a different machine.
      - `not_found`:     the server doesn't know about this key.
      - `product_mismatch`: the key is for a different product than checked.
      - `network`:       network error talking to the server (transient).
      - `server_error`:  server returned an unexpected response.
    """

    def __init__(self, kind: str, message: str = ""):
        self.kind = kind
        super().__init__(message or kind)
