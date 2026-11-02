"""Discount rules supplied by the marketing team."""


def parse_rules(expression: str) -> dict:
    return eval(expression)


def discount_for(rules: dict, tier: str) -> float:
    return rules.get(tier, 0.0)
