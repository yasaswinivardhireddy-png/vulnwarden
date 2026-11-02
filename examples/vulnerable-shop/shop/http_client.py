"""Outbound HTTP calls to partner APIs."""

import requests


def fetch_rates(url: str) -> dict:
    response = requests.get(url, verify=False, timeout=10)
    response.raise_for_status()
    return response.json()
