"""Follow-up automation: remind owners about idle remediation PRs and escalate when SLAs are at risk."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from .config import Config
from .github import GitHubClient
from .notify import Notifier
from .store import Store


class FollowUp(BaseModel):
    pr_number: int
    kind: str  # remind | escalate
    reason: str
    age_hours: float
    recipients: list[str] = Field(default_factory=list)
    url: str = ""
    delivered: list[str] = Field(default_factory=list)
    errors: dict[str, str] = Field(default_factory=dict)


def _parse(stamp: str) -> datetime:
    return datetime.fromisoformat(stamp.replace("Z", "+00:00"))


def evaluate_pull(
    pr: dict[str, Any],
    reviews: list[dict[str, Any]],
    now: datetime,
    config: Config,
    last_sent: dict[str, datetime | None],
) -> FollowUp | None:
    """Decide whether an open remediation PR needs a reminder or an escalation right now."""
    if pr.get("draft"):
        return None
    policy = config.monitor
    age = (now - _parse(pr["created_at"])).total_seconds() / 3600
    states = {r.get("state") for r in reviews}
    approved = "APPROVED" in states
    if age >= policy.escalate_after_hours and not pr.get("merged_at"):
        kind = "escalate"
        reason = f"Open for {age:.0f}h without merge (escalation threshold {policy.escalate_after_hours:.0f}h)." + (
            " Approved but not merged." if approved else ""
        )
    elif age >= policy.remind_after_hours:
        kind = "remind"
        if approved:
            reason = f"Approved {age:.0f}h ago but not merged."
        elif "CHANGES_REQUESTED" in states:
            reason = f"Changes requested; open for {age:.0f}h."
        elif not reviews:
            reason = f"No review after {age:.0f}h (reminder threshold {policy.remind_after_hours:.0f}h)."
        else:
            reason = f"Review in progress for {age:.0f}h without approval."
    else:
        return None
    previous = last_sent.get(kind)
    if previous is not None and (now - previous).total_seconds() / 3600 < policy.repeat_every_hours:
        return None
    recipients = sorted(
        {r["login"] for r in pr.get("requested_reviewers", []) if r.get("login")}
        | {a["login"] for a in pr.get("assignees", []) if a.get("login")}
        | set(config.owners)
    )
    if kind == "escalate":
        recipients = sorted(set(recipients) | set(config.escalation_contacts))
    return FollowUp(
        pr_number=pr["number"],
        kind=kind,
        reason=reason,
        age_hours=round(age, 1),
        recipients=recipients,
        url=pr.get("html_url", ""),
    )


def run_monitor(
    github: GitHubClient,
    store: Store,
    notifier: Notifier,
    config: Config,
    now: datetime | None = None,
    comment_on_pr: bool = True,
) -> list[FollowUp]:
    now = now or datetime.now(UTC)
    actions: list[FollowUp] = []
    for pr in github.list_open_pulls(label=config.monitor.label):
        reviews = github.list_reviews(pr["number"])
        last = {kind: store.last_notification(pr["number"], kind) for kind in ("remind", "escalate")}
        action = evaluate_pull(pr, reviews, now, config, last)
        if action is None:
            continue
        verb = "ESCALATION" if action.kind == "escalate" else "Reminder"
        subject = f"[VulnWarden] {verb}: security fix PR #{pr['number']} needs attention"
        body = f"{pr.get('title', '')}\n{action.reason}\n{action.url}"
        delivery = notifier.send(subject, body, action.recipients, escalation=action.kind == "escalate")
        action.delivered, action.errors = delivery.delivered, delivery.errors
        if comment_on_pr and not notifier.dry_run:
            mentions = " ".join(f"@{r}" for r in action.recipients if "@" not in r)
            github.comment(pr["number"], f"**VulnWarden {verb.lower()}:** {action.reason} {mentions}".strip())
        if not notifier.dry_run:
            store.record_notification(pr["number"], action.kind, delivery.delivered, action.recipients, now)
        store.audit("vulnwarden", f"pr_{action.kind}", action.model_dump(mode="json"), now)
        actions.append(action)
    return actions
