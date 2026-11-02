"""Product catalog loaded from YAML."""

import yaml


def load_catalog(text: str) -> dict:
    return yaml.load(text, Loader=yaml.Loader)


def price_of(catalog: dict, name: str) -> int:
    return next(item["price"] for item in catalog["items"] if item["name"] == name)
