"""Online HTTP client for the Keysat REST API.

Wraps the public endpoints (`/v1/validate`, `/v1/purchase`,
`/v1/redeem`, `/v1/machines/*`) over HTTPS. All methods are synchronous;
an async variant can be added later if anyone asks.

Requires `httpx`. Install via the `online` extra::

    pip install keysat-licensing-client[online]
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import httpx  # imported only when this module is loaded; gated in __init__.py

from .errors import LicensingError


# ---------- Response shapes ----------


@dataclass
class ValidateResponse:
    ok: bool
    reason: str | None = None
    license_id: str | None = None
    product_id: str | None = None
    product_slug: str | None = None
    issued_at: str | None = None
    expires_at: str | None = None
    grace_until: str | None = None
    in_grace_period: bool | None = None
    is_trial: bool | None = None
    entitlements: list[str] = field(default_factory=list)
    status: str | None = None
    machine_id: str | None = None
    max_machines: int | None = None


@dataclass
class ValidateOptions:
    product_slug: str | None = None
    fingerprint: str | None = None
    hostname: str | None = None
    platform: str | None = None


@dataclass
class StartPurchaseOptions:
    """Optional extras for :meth:`Client.start_purchase`.

    All fields are optional. To buy a specific tier, set
    ``policy_slug`` to one of the slugs returned by
    :meth:`Client.list_public_policies`. When omitted, the
    licensing service falls back to the product's default policy.
    """

    buyer_email: str | None = None
    buyer_note: str | None = None
    redirect_url: str | None = None
    code: str | None = None
    policy_slug: str | None = None


@dataclass
class PublicPolicy:
    """One tier returned by :meth:`Client.list_public_policies`.

    Mirrors what the licensing service's ``/buy/<slug>`` page reads
    server-side, so an in-app tier picker can render identical text
    and pricing.
    """

    slug: str
    name: str
    description: str
    price_sats: int
    duration_seconds: int
    max_machines: int
    is_trial: bool
    entitlements: list[str]
    highlighted: bool
    is_recurring: bool
    renewal_period_days: int
    trial_days: int


@dataclass
class PublicPoliciesProduct:
    slug: str
    name: str
    description: str
    base_price_sats: int


@dataclass
class PublicPoliciesResponse:
    product: PublicPoliciesProduct
    policies: list[PublicPolicy]


@dataclass
class PurchaseSession:
    invoice_id: str
    btcpay_invoice_id: str
    checkout_url: str
    amount_sats: int
    base_price_sats: int
    discount_applied_sats: int
    poll_url: str


@dataclass
class PollResponse:
    invoice_id: str
    status: str  # 'pending' | 'settled' | 'expired' | 'invalid'
    product_id: str
    amount_sats: int
    license_key: str | None
    license_id: str | None


@dataclass
class RedeemFreeOptions:
    buyer_email: str | None = None
    buyer_note: str | None = None


@dataclass
class RedeemFreeResponse:
    license_id: str
    license_key: str
    invoice_id: str
    redemption_id: str


@dataclass
class MachineResponse:
    ok: bool
    reason: str | None = None
    machine_id: str | None = None
    active_count: int | None = None
    max_machines: int | None = None


# ---------- Client ----------


class Client:
    """HTTP client pinned to one Keysat server URL.

    Construct with the public base URL (e.g. ``https://license.example.com``).
    All methods raise `LicensingError(kind="network")` on transport
    failure and `LicensingError(kind="server_error")` on unexpected
    server responses; semantic-failure cases (revoked / fingerprint
    mismatch / bad signature) come back as `ValidateResponse(ok=False,
    reason="...")` so the caller can render different messaging per
    reason without try/except.
    """

    def __init__(self, base_url: str, *, timeout: float = 15.0):
        self._base = base_url.rstrip("/")
        self._timeout = timeout

    @property
    def base_url(self) -> str:
        return self._base

    # ----- Public endpoints -----

    def fetch_pubkey_pem(self) -> str:
        data = self._get("/v1/pubkey")
        return data["public_key_pem"]

    def validate(
        self,
        key: str,
        product_slug: str | None = None,
        fingerprint: str | None = None,
        opts: ValidateOptions | None = None,
    ) -> ValidateResponse:
        merged = opts or ValidateOptions()
        body = {
            "key": key,
            "product_slug": merged.product_slug or product_slug,
            "fingerprint": merged.fingerprint or fingerprint,
            "hostname": merged.hostname,
            "platform": merged.platform,
        }
        body = {k: v for k, v in body.items() if v is not None}
        raw = self._post("/v1/validate", body)
        ents = raw.get("entitlements") or []
        return ValidateResponse(
            ok=bool(raw.get("ok")),
            reason=raw.get("reason"),
            license_id=raw.get("license_id"),
            product_id=raw.get("product_id"),
            product_slug=raw.get("product_slug"),
            issued_at=raw.get("issued_at"),
            expires_at=raw.get("expires_at"),
            grace_until=raw.get("grace_until"),
            in_grace_period=raw.get("in_grace_period"),
            is_trial=raw.get("is_trial"),
            entitlements=[e for e in ents if isinstance(e, str)],
            status=raw.get("status"),
            machine_id=raw.get("machine_id"),
            max_machines=raw.get("max_machines"),
        )

    # ----- Machine seat management -----

    def heartbeat(self, key: str, fingerprint: str) -> MachineResponse:
        raw = self._post("/v1/machines/heartbeat", {"key": key, "fingerprint": fingerprint})
        return _to_machine_response(raw)

    def activate(
        self,
        key: str,
        fingerprint: str,
        hostname: str | None = None,
        platform: str | None = None,
    ) -> MachineResponse:
        body = {"key": key, "fingerprint": fingerprint, "hostname": hostname, "platform": platform}
        body = {k: v for k, v in body.items() if v is not None}
        raw = self._post("/v1/machines/activate", body)
        return _to_machine_response(raw)

    def deactivate(
        self, key: str, fingerprint: str, reason: str | None = None
    ) -> MachineResponse:
        body = {"key": key, "fingerprint": fingerprint, "reason": reason}
        body = {k: v for k, v in body.items() if v is not None}
        raw = self._post("/v1/machines/deactivate", body)
        return _to_machine_response(raw)

    # ----- Purchase flow -----

    def start_purchase(
        self,
        product_slug: str,
        opts: StartPurchaseOptions | None = None,
    ) -> PurchaseSession:
        merged = opts or StartPurchaseOptions()
        body = {
            "product": product_slug,
            "buyer_email": merged.buyer_email,
            "buyer_note": merged.buyer_note,
            "redirect_url": merged.redirect_url,
            "code": merged.code,
            "policy_slug": merged.policy_slug,
        }
        body = {k: v for k, v in body.items() if v is not None}
        raw = self._post("/v1/purchase", body)
        return PurchaseSession(
            invoice_id=raw["invoice_id"],
            btcpay_invoice_id=raw["btcpay_invoice_id"],
            checkout_url=raw["checkout_url"],
            amount_sats=raw["amount_sats"],
            base_price_sats=raw.get("base_price_sats", raw["amount_sats"]),
            discount_applied_sats=raw.get("discount_applied_sats", 0),
            poll_url=raw["poll_url"],
        )

    def list_public_policies(self, product_slug: str) -> PublicPoliciesResponse:
        """List public, buyer-visible policies (tiers) for a product.

        No auth required — same data the licensing service's
        ``/buy/<slug>`` page reads server-side. Use this to render an
        in-app tier picker that stays in sync with the operator's
        admin-side tier setup. Internal fields (id, tip recipients,
        raw metadata) are omitted by the server.
        """
        raw = self._get(f"/v1/products/{product_slug}/policies")
        product = raw.get("product", {}) or {}
        policies_raw = raw.get("policies") or []
        return PublicPoliciesResponse(
            product=PublicPoliciesProduct(
                slug=product.get("slug", ""),
                name=product.get("name", ""),
                description=product.get("description", "") or "",
                base_price_sats=int(product.get("base_price_sats", 0)),
            ),
            policies=[
                PublicPolicy(
                    slug=p.get("slug", ""),
                    name=p.get("name", ""),
                    description=p.get("description", "") or "",
                    price_sats=int(p.get("price_sats", 0)),
                    duration_seconds=int(p.get("duration_seconds", 0)),
                    max_machines=int(p.get("max_machines", 1)),
                    is_trial=bool(p.get("is_trial", False)),
                    entitlements=list(p.get("entitlements") or []),
                    highlighted=bool(p.get("highlighted", False)),
                    is_recurring=bool(p.get("is_recurring", False)),
                    renewal_period_days=int(p.get("renewal_period_days", 0)),
                    trial_days=int(p.get("trial_days", 0)),
                )
                for p in policies_raw
            ],
        )

    def poll_purchase(self, invoice_id: str) -> PollResponse:
        raw = self._get(f"/v1/purchase/{invoice_id}")
        return PollResponse(
            invoice_id=raw["invoice_id"],
            status=raw["status"],
            product_id=raw["product_id"],
            amount_sats=raw["amount_sats"],
            license_key=raw.get("license_key"),
            license_id=raw.get("license_id"),
        )

    def wait_for_license(
        self,
        invoice_id: str,
        interval_s: float = 5.0,
        timeout_s: float | None = None,
    ) -> str:
        """Poll `poll_purchase` until the license_key is non-null.

        Raises LicensingError on terminal invoice states (expired /
        invalid) or timeout. Returns the license_key string on success.
        """
        deadline = time.monotonic() + timeout_s if timeout_s else None
        while True:
            poll = self.poll_purchase(invoice_id)
            if poll.license_key:
                return poll.license_key
            if poll.status in ("expired", "invalid"):
                raise LicensingError(
                    "server_error", f"invoice ended in status {poll.status}"
                )
            if deadline is not None and time.monotonic() > deadline:
                raise LicensingError(
                    "server_error", "timed out waiting for license issuance"
                )
            time.sleep(interval_s)

    # ----- Free-license redemption -----

    def redeem_free_license(
        self,
        product_slug: str,
        code: str,
        opts: RedeemFreeOptions | None = None,
    ) -> RedeemFreeResponse:
        merged = opts or RedeemFreeOptions()
        body = {
            "product": product_slug,
            "code": code,
            "buyer_email": merged.buyer_email,
            "buyer_note": merged.buyer_note,
        }
        body = {k: v for k, v in body.items() if v is not None}
        raw = self._post("/v1/redeem", body)
        return RedeemFreeResponse(
            license_id=raw["license_id"],
            license_key=raw["license_key"],
            invoice_id=raw["invoice_id"],
            redemption_id=raw["redemption_id"],
        )

    # ----- Internals -----

    def _get(self, path: str) -> dict[str, Any]:
        return self._request("GET", path, json_body=None)

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", path, json_body=body)

    def _request(self, method: str, path: str, json_body: dict[str, Any] | None) -> dict[str, Any]:
        url = self._base + path
        try:
            resp = httpx.request(method, url, json=json_body, timeout=self._timeout)
        except httpx.HTTPError as e:
            raise LicensingError("network", f"{method} {url}: {e}") from e
        if resp.status_code >= 500:
            raise LicensingError(
                "server_error",
                f"{method} {url}: HTTP {resp.status_code} — {resp.text[:200]}",
            )
        if resp.status_code >= 400:
            raise LicensingError(
                "server_error",
                f"{method} {url}: HTTP {resp.status_code} — {resp.text[:200]}",
            )
        try:
            return resp.json()
        except Exception as e:
            raise LicensingError(
                "server_error",
                f"{method} {url}: response was not JSON: {e}",
            ) from e


def _to_machine_response(raw: dict[str, Any]) -> MachineResponse:
    return MachineResponse(
        ok=bool(raw.get("ok")),
        reason=raw.get("reason"),
        machine_id=raw.get("machine_id"),
        active_count=raw.get("active_count"),
        max_machines=raw.get("max_machines"),
    )
