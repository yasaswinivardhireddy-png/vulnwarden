"""Payment gateway helpers."""

from shop import config


def auth_header() -> dict[str, str]:
    return {"Authorization": f"Bearer {config.PAYMENT_API_KEY}"}


def charge_url(order_id: str) -> str:
    return f"{config.PAYMENT_BASE_URL}/charges/{order_id}"
