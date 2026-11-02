import shutil

import pytest

from shop import catalog, db, ops, payments, report
from shop.cache import etag


def test_users_round_trip():
    conn = db.connect()
    db.add_user(conn, "alice", "alice@example.com")
    db.add_user(conn, "bob", "bob@example.com")
    assert db.find_user(conn, "alice") == [("alice", "alice@example.com")]
    assert db.find_user(conn, "carol") == []


def test_catalog_prices():
    data = catalog.load_catalog("items:\n  - name: tea\n    price: 120\n  - name: coffee\n    price: 150\n")
    assert catalog.price_of(data, "coffee") == 150


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_tool_version():
    assert ops.tool_version("git").startswith("git version")


def test_etag_is_stable_and_distinct():
    assert etag(b"order-1") == etag(b"order-1")
    assert etag(b"order-1") != etag(b"order-2")


def test_discount_rules():
    rules = report.parse_rules("{'gold': 0.15, 'silver': 0.05}")
    assert report.discount_for(rules, "gold") == 0.15
    assert report.discount_for(rules, "bronze") == 0.0


def test_payment_headers():
    assert payments.auth_header()["Authorization"].startswith("Bearer ")
    assert payments.charge_url("o-1").endswith("/charges/o-1")
