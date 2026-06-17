# keysat-licensing-client (Python)

Python client for [Keysat](https://github.com/keysat-xyz/keysat) — a
Bitcoin-native self-hosted software licensing service that runs on Start9.

Verifies signed license keys offline using the issuer's public key, and
(optionally) wraps the HTTP API for live validation, purchase, and
free-license redemption.

## Install

```bash
pip install keysat-licensing-client            # offline only
pip install keysat-licensing-client[online]    # + httpx for the online client
```

Requires Python 3.10+.

## Five-line offline check

```python
from keysat_licensing_client import Verifier, PublicKey

ISSUER_PUBKEY_PEM = open("assets/issuer.pub").read()  # bake this into your app
verifier = Verifier(PublicKey.from_pem(ISSUER_PUBKEY_PEM))

ok = verifier.verify(key_from_user)  # raises LicensingError on bad sig
# ok.expires_at is a unix timestamp; 0 = perpetual
print(f"licensed for product {ok.product_id}, expires {ok.expires_at}")
```

## Online check (with revocation + fingerprint binding)

```python
from keysat_licensing_client import Client

client = Client("https://license.example.com")
r = client.validate(
    key_from_user,
    product_slug="my-product",
    fingerprint="machine-fingerprint",
)
if not r.ok:
    print("server rejected:", r.reason)
    # 'revoked', 'fingerprint_mismatch', 'not_found', 'product_mismatch', etc.
```

The recommended pattern is **offline-first, online-augmented**: do the
offline `Verifier.verify()` at boot. If that succeeds, also do an
async/background `client.validate()` to catch revocations and seat
mismatches. If the network fails, treat it as "status unknown" — don't
gate the user on your server's uptime.

## Purchase flow (drives the whole BTCPay round trip)

```python
from keysat_licensing_client import Client, StartPurchaseOptions
import webbrowser

client = Client("https://license.example.com")
session = client.start_purchase(
    "my-product",
    StartPurchaseOptions(buyer_email="bob@example.com"),
)
webbrowser.open(session.checkout_url)
license_key = client.wait_for_license(session.invoice_id)
# Save license_key wherever you decided to store keys (config dir, keychain, env).
```

To buy a specific tier, set `StartPurchaseOptions(policy_slug=...)` to a
slug from `list_public_policies` (below); omit it to use the product's
default policy.

## Tier picker (public policies)

List the buyer-visible tiers for a product — same data the server's
`/buy/<slug>` page reads, so an in-app picker stays in sync with the
operator's admin setup. No auth required.

```python
tiers = client.list_public_policies("my-product")
for p in tiers.policies:
    print(p.slug, p.name, p.price_sats, "sats", p.max_machines, "seats")
# tiers.product.entitlements_catalog maps entitlement slugs -> human labels.
```

## Machine seat management

For seat-limited licenses (`max_machines > 1`), claim and release seats by
fingerprint. Each returns a `MachineResponse` (`ok`, `reason`,
`active_count`, `max_machines`).

```python
client.activate(key, fingerprint, hostname="bob-laptop", platform="macos")
client.heartbeat(key, fingerprint)   # call periodically to keep the seat live
client.deactivate(key, fingerprint)  # release the seat
```

## Free-license code redemption

For codes the seller created with kind `free_license` (no payment):

```python
result = client.redeem_free_license(
    "my-product",
    "PRESSPASS",
)
print("redeemed:", result.license_key)
```

## Fingerprint binding

The SDK doesn't decide WHAT to use as a fingerprint — that's a product
choice. Common sources, ordered by robustness:

- Linux: `/etc/machine-id`
- macOS: `ioreg -d2 -c IOPlatformExpertDevice`
- Windows: registry `MachineGuid`
- Fallback: random UUID written into your app's config dir on first run

Mix in a per-product salt so fingerprints from your app can't be
replayed against someone else's licensing server:

```python
fp_input = f"{APP_NAME}|{machine_id}"
# Pass this raw string to validate(...); the server SHA-256s it before storing.
```

## License

MIT OR Apache-2.0. See the upstream `LICENSE` file at
[github.com/keysat-xyz/keysat](https://github.com/keysat-xyz/keysat).
