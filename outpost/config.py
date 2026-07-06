"""Outpost configuration — read from the environment (or a `.env` loaded by the
service manager). Kept tiny and dependency-free so it works before anything else
is wired up.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    url: str
    token: str
    poll_seconds: int = 15
    verify_tls: bool = True

    @property
    def base(self) -> str:
        return self.url.rstrip("/")

    @property
    def work_url(self) -> str:
        return f"{self.base}/api/outpost/work/"

    @property
    def results_url(self) -> str:
        return f"{self.base}/api/outpost/results/"

    @property
    def hello_url(self) -> str:
        return f"{self.base}/api/outpost/hello/"

    @property
    def snmp_work_url(self) -> str:
        return f"{self.base}/api/outpost/snmp-work/"

    @property
    def snmp_results_url(self) -> str:
        return f"{self.base}/api/outpost/snmp/"


class ConfigError(RuntimeError):
    pass


def load(overrides: dict | None = None) -> Config:
    """Config from the environment, with CLI ``overrides`` (``--url``/``--token``/
    …) winning — so a one-liner works without exporting anything first."""
    o = overrides or {}
    url = (o.get("url") or os.environ.get("OUTPOST_URL", "")).strip()
    token = (o.get("token") or os.environ.get("OUTPOST_TOKEN", "")).strip()
    if not url or not token:
        raise ConfigError(
            "OUTPOST_URL and OUTPOST_TOKEN are required — pass --url/--token or "
            "set them in the environment. Create an Outpost in Danbyte → "
            "Governance → Monitoring engines and enroll it for the one-liner."
        )
    return Config(
        url=url,
        token=token,
        poll_seconds=int(
            o.get("poll") or os.environ.get("OUTPOST_POLL_SECONDS", "15")
        ),
        verify_tls=(
            o.get("verify_tls")
            if o.get("verify_tls") is not None
            else os.environ.get("OUTPOST_VERIFY_TLS", "1") != "0"
        ),
    )
