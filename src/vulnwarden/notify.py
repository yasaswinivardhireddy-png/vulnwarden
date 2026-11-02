"""Notification channels: console, email (SMTP + STARTTLS), Slack and Microsoft Teams webhooks."""

from __future__ import annotations

import os
import smtplib
import ssl
from collections.abc import Callable, Mapping
from email.message import EmailMessage
from typing import Any

import httpx
from pydantic import BaseModel, Field

from .config import NotifyConfig


class Delivery(BaseModel):
    delivered: list[str] = Field(default_factory=list)
    errors: dict[str, str] = Field(default_factory=dict)


class Notifier:
    def __init__(
        self,
        config: NotifyConfig,
        *,
        env: Mapping[str, str] | None = None,
        transport: httpx.BaseTransport | None = None,
        smtp_factory: Callable[..., Any] = smtplib.SMTP,
        echo: Callable[[str], None] = print,
        dry_run: bool = False,
    ) -> None:
        self.config = config
        self.env = env if env is not None else os.environ
        self.transport = transport
        self.smtp_factory = smtp_factory
        self.echo = echo
        self.dry_run = dry_run

    def send(self, subject: str, body: str, recipients: list[str], escalation: bool = False) -> Delivery:
        delivery = Delivery()
        for channel in self.config.channels:
            try:
                if self.dry_run or channel == "console":
                    prefix = "[dry-run] " if self.dry_run and channel != "console" else ""
                    self.echo(f"{prefix}[{channel}] {subject} -> {', '.join(recipients) or 'owners'}\n{body}")
                elif channel == "email":
                    self._email(subject, body, recipients, escalation)
                elif channel in {"slack", "teams"}:
                    self._webhook(channel, subject, body, recipients)
                else:
                    raise ValueError(f"unknown channel '{channel}'")
                delivery.delivered.append(channel)
            except Exception as exc:  # one failing channel must not block the others
                delivery.errors[channel] = f"{type(exc).__name__}: {exc}"
        return delivery

    def _email(self, subject: str, body: str, recipients: list[str], escalation: bool) -> None:
        if not self.config.smtp_host:
            raise ValueError("notify.smtp_host is not configured")
        to = list(self.config.email_to) + [r for r in recipients if "@" in r]
        if escalation:
            to += self.config.escalation_email_to
        to = sorted(set(to))
        if not to:
            raise ValueError("no email recipients configured")
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = self.config.smtp_sender
        message["To"] = ", ".join(to)
        message.set_content(body)
        with self.smtp_factory(self.config.smtp_host, self.config.smtp_port, timeout=30) as smtp:
            smtp.starttls(context=ssl.create_default_context())
            username = self.env.get(self.config.smtp_username_env)
            password = self.env.get(self.config.smtp_password_env)
            if username and password:
                smtp.login(username, password)
            smtp.send_message(message)

    def _webhook(self, channel: str, subject: str, body: str, recipients: list[str]) -> None:
        variable = self.config.slack_webhook_env if channel == "slack" else self.config.teams_webhook_env
        url = self.env.get(variable)
        if not url:
            raise ValueError(f"{variable} is not set")
        if not url.startswith("https://"):
            raise ValueError("webhook URL must use https")
        mentions = " ".join(f"@{r}" for r in recipients if "@" not in r)
        text = f"*{subject}*\n{body}" if channel == "slack" else f"**{subject}**\n\n{body}"
        if mentions:
            text += f"\n{mentions}"
        with httpx.Client(timeout=15, transport=self.transport) as client:
            response = client.post(url, json={"text": text})
            response.raise_for_status()
