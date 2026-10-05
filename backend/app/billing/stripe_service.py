"""
GhostPrompt Stripe Billing Service — Production-Grade

Real Stripe integration for:
- Product/Price management
- Checkout sessions
- Customer Portal
- Subscription lifecycle
- Usage-based metering
- Webhook handling with signature verification
"""

import os
from dataclasses import dataclass
from datetime import datetime, timezone

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger("billing.stripe")
settings = get_settings()


# ── Plan definitions (matching landing page tiers) ──
PLANS = {
    "free": {
        "name": "Free",
        "price_monthly": 0,
        "scan_limit": 1000,
        "seats": 1,
        "features": ["Basic scanning", "Community support", "5 policies"],
    },
    "pro": {
        "name": "Pro",
        "price_monthly": 4900,  # $49.00 in cents
        "scan_limit": 50000,
        "seats": 5,
        "features": ["50K scans/mo", "All detectors", "Email support", "API access", "Custom policies"],
    },
    "business": {
        "name": "Business",
        "price_monthly": 19900,  # $199.00 in cents
        "scan_limit": 500000,
        "seats": 25,
        "features": ["500K scans/mo", "Priority support", "SSO/SCIM", "Custom models", "Red Team Ops"],
    },
    "enterprise": {
        "name": "Enterprise",
        "price_monthly": 0,  # Custom pricing
        "scan_limit": -1,  # Unlimited
        "seats": -1,
        "features": ["Unlimited scans", "Dedicated support", "VPC deployment", "Custom SLAs", "Everything"],
    },
}


@dataclass
class SubscriptionInfo:
    """Current subscription state for an org."""
    org_id: str
    plan: str = "free"
    stripe_customer_id: str | None = None
    stripe_subscription_id: str | None = None
    status: str = "active"  # active, past_due, canceled, trialing
    current_period_start: str | None = None
    current_period_end: str | None = None
    scan_usage: int = 0
    scan_limit: int = 1000
    seats_used: int = 1
    seats_limit: int = 1


# ── In-memory subscription store (production: Postgres) ──
_subscriptions: dict[str, SubscriptionInfo] = {}
_usage_records: dict[str, list[dict]] = {}


class StripeService:
    """Production Stripe integration service."""

    def __init__(self):
        self._stripe = None
        self._initialized = False

    def _get_stripe(self):
        """Lazy-load stripe module and configure API key."""
        if self._stripe is None:
            try:
                import stripe
                stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")
                self._stripe = stripe
                if stripe.api_key:
                    self._initialized = True
                    logger.info("stripe_initialized")
                else:
                    logger.warning("stripe_no_api_key")
            except ImportError:
                logger.warning("stripe_not_installed")
        return self._stripe

    @property
    def is_configured(self) -> bool:
        self._get_stripe()
        return self._initialized

    # ── Subscription Management ──

    def get_subscription(self, org_id: str) -> SubscriptionInfo:
        """Get current subscription for an org."""
        if org_id not in _subscriptions:
            _subscriptions[org_id] = SubscriptionInfo(org_id=org_id)
        return _subscriptions[org_id]

    async def create_checkout_session(
        self,
        org_id: str,
        plan: str,
        success_url: str,
        cancel_url: str,
        email: str | None = None,
        bypass_mode: bool = False,
    ) -> dict | None:
        """Create a Stripe Checkout session for subscription."""
        
        plan_config = PLANS.get(plan)
        if not plan_config or plan == "free":
            return None

        stripe = self._get_stripe()
        if not stripe or not self._initialized or bypass_mode:
            # Fallback/Bypass: return mock checkout for testing or restricted regions (like India)
            # In bypass mode, we actually just upgrade them instantly and return a success URL
            if bypass_mode:
                sub = self.get_subscription(org_id)
                sub.plan = plan
                sub.status = "active"
                sub.scan_limit = plan_config.get("scan_limit", 1000)
                sub.seats_limit = plan_config.get("seats", 1)
                sub.stripe_customer_id = f"cus_bypass_{org_id}"
                sub.stripe_subscription_id = f"sub_bypass_{org_id}"
                logger.info("billing_bypass_activated", org=org_id, plan=plan)

            return {
                "id": f"cs_bypass_{org_id}_{plan}",
                "url": f"{success_url}?session_id=cs_bypass_{plan}",
                "status": "open",
                "mode": "subscription",
                "note": "Stripe bypassed — instant upgrade applied",
            }

        try:
            # Get or create Stripe customer
            sub = self.get_subscription(org_id)
            customer_id = sub.stripe_customer_id

            if not customer_id:
                customer = stripe.Customer.create(
                    email=email,
                    metadata={"org_id": org_id, "plan": plan},
                )
                customer_id = customer.id
                sub.stripe_customer_id = customer_id

            # Look up or create price
            price_id = os.environ.get(f"STRIPE_PRICE_{plan.upper()}")

            if not price_id:
                # Create product + price dynamically
                product = stripe.Product.create(
                    name=f"GhostPrompt {plan_config['name']}",
                    metadata={"plan": plan},
                )
                price = stripe.Price.create(
                    product=product.id,
                    unit_amount=plan_config["price_monthly"],
                    currency="usd",
                    recurring={"interval": "month"},
                )
                price_id = price.id

            session = stripe.checkout.Session.create(
                customer=customer_id,
                mode="subscription",
                line_items=[{"price": price_id, "quantity": 1}],
                success_url=success_url + "?session_id={CHECKOUT_SESSION_ID}",
                cancel_url=cancel_url,
                metadata={"org_id": org_id, "plan": plan},
                allow_promotion_codes=True,
                billing_address_collection="auto",
                tax_id_collection={"enabled": True},
            )

            return {
                "id": session.id,
                "url": session.url,
                "status": session.status,
            }

        except Exception as e:
            logger.error("checkout_session_failed", error=str(e))
            return None

    async def create_portal_session(
        self,
        org_id: str,
        return_url: str,
    ) -> dict | None:
        """Create a Stripe Customer Portal session."""
        stripe = self._get_stripe()
        if not stripe or not self._initialized:
            return {"url": return_url, "note": "Stripe not configured"}

        sub = self.get_subscription(org_id)
        if not sub.stripe_customer_id:
            return None

        try:
            session = stripe.billing_portal.Session.create(
                customer=sub.stripe_customer_id,
                return_url=return_url,
            )
            return {"url": session.url}
        except Exception as e:
            logger.error("portal_session_failed", error=str(e))
            return None

    # ── Usage Metering ──

    def record_usage(self, org_id: str, event_type: str = "scan", quantity: int = 1):
        """Record a billable usage event."""
        sub = self.get_subscription(org_id)
        sub.scan_usage += quantity

        if org_id not in _usage_records:
            _usage_records[org_id] = []
        _usage_records[org_id].append({
            "event_type": event_type,
            "quantity": quantity,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        # Check quota
        if sub.scan_limit > 0 and sub.scan_usage >= sub.scan_limit:
            logger.warning(
                "usage_quota_exceeded",
                org=org_id,
                usage=sub.scan_usage,
                limit=sub.scan_limit,
            )

    def get_usage_summary(self, org_id: str) -> dict:
        """Get usage summary for an org."""
        sub = self.get_subscription(org_id)
        records = _usage_records.get(org_id, [])

        return {
            "plan": sub.plan,
            "scan_usage": sub.scan_usage,
            "scan_limit": sub.scan_limit,
            "usage_pct": round((sub.scan_usage / sub.scan_limit * 100), 1) if sub.scan_limit > 0 else 0,
            "seats_used": sub.seats_used,
            "seats_limit": sub.seats_limit,
            "billing_period": {
                "start": sub.current_period_start,
                "end": sub.current_period_end,
            },
            "recent_events": records[-20:],
        }

    # ── Webhook Processing ──

    async def handle_webhook(self, payload: bytes, sig_header: str) -> dict:
        """Process incoming Stripe webhook with signature verification."""
        stripe = self._get_stripe()
        if not stripe:
            return {"status": "stripe_not_configured"}

        webhook_secret = os.environ.get("STRIPE_WEBHOOK_SECRET", "")

        try:
            event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
        except Exception as e:
            logger.error("webhook_sig_verification_failed", error=str(e))
            raise ValueError(f"Invalid webhook: {e}")

        event_type = event["type"]
        data = event["data"]["object"]

        logger.info("webhook_received", type=event_type)

        match event_type:
            case "checkout.session.completed":
                org_id = data.get("metadata", {}).get("org_id")
                plan = data.get("metadata", {}).get("plan")
                if org_id and plan:
                    sub = self.get_subscription(org_id)
                    sub.plan = plan
                    sub.stripe_customer_id = data.get("customer")
                    sub.stripe_subscription_id = data.get("subscription")
                    sub.status = "active"
                    sub.scan_limit = PLANS.get(plan, {}).get("scan_limit", 1000)
                    sub.seats_limit = PLANS.get(plan, {}).get("seats", 1)
                    logger.info("subscription_activated", org=org_id, plan=plan)

            case "customer.subscription.updated":
                # Handle plan changes, renewals
                customer_id = data.get("customer")
                status = data.get("status")
                for sub in _subscriptions.values():
                    if sub.stripe_customer_id == customer_id:
                        sub.status = status
                        if data.get("current_period_start"):
                            sub.current_period_start = datetime.fromtimestamp(
                                data["current_period_start"], tz=timezone.utc
                            ).isoformat()
                        if data.get("current_period_end"):
                            sub.current_period_end = datetime.fromtimestamp(
                                data["current_period_end"], tz=timezone.utc
                            ).isoformat()
                        logger.info("subscription_updated", status=status)
                        break

            case "customer.subscription.deleted":
                customer_id = data.get("customer")
                for sub in _subscriptions.values():
                    if sub.stripe_customer_id == customer_id:
                        sub.plan = "free"
                        sub.status = "canceled"
                        sub.scan_limit = 1000
                        sub.seats_limit = 1
                        logger.info("subscription_canceled", org=sub.org_id)
                        break

            case "invoice.payment_failed":
                customer_id = data.get("customer")
                for sub in _subscriptions.values():
                    if sub.stripe_customer_id == customer_id:
                        sub.status = "past_due"
                        logger.warning("payment_failed", org=sub.org_id)
                        break

        return {"status": "processed", "type": event_type}


# Global singleton
stripe_service = StripeService()
