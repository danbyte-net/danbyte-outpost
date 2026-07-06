"""HTTPS client for the pull transport — the Outpost dials out to Danbyte."""
from __future__ import annotations

import platform

import httpx

from . import PROTOCOL_VERSION, __version__
from .config import Config


class OutpostClient:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._http = httpx.AsyncClient(
            verify=cfg.verify_tls,
            timeout=30.0,
            headers={
                "Authorization": f"Bearer {cfg.token}",
                "User-Agent": f"danbyte-outpost/{__version__}",
            },
        )

    async def aclose(self):
        await self._http.aclose()

    async def hello(self) -> dict:
        r = await self._http.post(
            self.cfg.hello_url,
            json={
                "version": __version__,
                "protocol": PROTOCOL_VERSION,
                "hostname": platform.node(),
            },
        )
        r.raise_for_status()
        return r.json()

    async def fetch_work(self) -> dict:
        """→ {checks, poll_interval_seconds, sweep_pending}."""
        r = await self._http.get(self.cfg.work_url)
        r.raise_for_status()
        return r.json()

    async def post_results(self, results: list[dict]) -> int:
        if not results:
            return 0
        r = await self._http.post(self.cfg.results_url, json={"results": results})
        r.raise_for_status()
        return r.json().get("ingested", 0)

    async def download_binary(self, version: str) -> bytes:
        """Download a release's binary artifact (auth'd by the Outpost token)."""
        r = await self._http.get(
            f"{self.cfg.base}/api/outpost/download/{version}/"
        )
        r.raise_for_status()
        return r.content

    async def fetch_snmp_work(self) -> dict:
        """SNMP discovery targets + creds for this Outpost → {devices, interval_seconds}."""
        r = await self._http.get(self.cfg.snmp_work_url)
        r.raise_for_status()
        return r.json()

    async def post_snmp_results(self, results: list[dict]) -> int:
        if not results:
            return 0
        r = await self._http.post(
            self.cfg.snmp_results_url, json={"results": results}
        )
        r.raise_for_status()
        return r.json().get("ingested", 0)

    async def fetch_sweep_work(self) -> dict:
        """Discovery prefixes to sweep → {prefixes, interval_seconds}."""
        r = await self._http.get(self.cfg.sweep_work_url)
        r.raise_for_status()
        return r.json()

    async def post_discovered(self, results: list[dict]) -> int:
        if not results:
            return 0
        r = await self._http.post(
            self.cfg.discovered_url, json={"results": results}
        )
        r.raise_for_status()
        return r.json().get("created", 0)
