"""Core IP checking functionality with async support."""

from __future__ import annotations

import asyncio
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

import dns.resolver
import httpx

from .config import DNSBLS, THREAT_FEEDS


class ThreatLevel(Enum):
    """Threat level classification."""
    CLEAN = "clean"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class CheckResult:
    """Result of a single blacklist check."""
    source: str
    source_type: str  # "dnsbl" or "http_feed"
    listed: bool
    details: str | None = None
    error: str | None = None
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "source": self.source,
            "source_type": self.source_type,
            "listed": self.listed,
            "details": self.details,
            "error": self.error,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class IPReport:
    """Complete report for an IP address."""
    ip: str
    fqdn: str | None = None
    geo_info: dict | None = None
    results: list[CheckResult] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)

    @property
    def total_checks(self) -> int:
        """Total number of successful checks."""
        return len([r for r in self.results if r.error is None])

    @property
    def blacklist_count(self) -> int:
        """Number of blacklists the IP is listed on."""
        return len([r for r in self.results if r.listed])

    @property
    def clean_count(self) -> int:
        """Number of blacklists the IP is NOT listed on."""
        return len([r for r in self.results if not r.listed and r.error is None])

    @property
    def error_count(self) -> int:
        """Number of checks that failed."""
        return len([r for r in self.results if r.error is not None])

    @property
    def threat_level(self) -> ThreatLevel:
        """Calculate overall threat level based on blacklist hits."""
        if self.total_checks == 0:
            return ThreatLevel.CLEAN

        ratio = self.blacklist_count / max(self.total_checks, 1)

        if self.blacklist_count == 0:
            return ThreatLevel.CLEAN
        elif self.blacklist_count <= 2 or ratio < 0.1:
            return ThreatLevel.LOW
        elif self.blacklist_count <= 5 or ratio < 0.25:
            return ThreatLevel.MEDIUM
        elif self.blacklist_count <= 10 or ratio < 0.5:
            return ThreatLevel.HIGH
        else:
            return ThreatLevel.CRITICAL

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "ip": self.ip,
            "fqdn": self.fqdn,
            "geo_info": self.geo_info,
            "summary": {
                "total_checks": self.total_checks,
                "blacklist_count": self.blacklist_count,
                "clean_count": self.clean_count,
                "error_count": self.error_count,
                "threat_level": self.threat_level.value,
            },
            "results": [r.to_dict() for r in self.results],
            "timestamp": self.timestamp.isoformat(),
        }


class IPChecker:
    """Async IP reputation checker."""

    def __init__(
        self,
        timeout: float = 5.0,
        dns_timeout: float = 5.0,
        max_concurrent: int = 20,
    ):
        self.timeout = timeout
        self.dns_timeout = dns_timeout
        self.max_concurrent = max_concurrent
        self._http_client: httpx.AsyncClient | None = None
        self._feed_cache: dict[str, set[str]] = {}

    async def __aenter__(self) -> IPChecker:
        self._http_client = httpx.AsyncClient(
            timeout=self.timeout,
            headers={"User-Agent": "IsThisIPBad/2.0"},
            follow_redirects=True,
        )
        return self

    async def __aexit__(self, *args) -> None:
        if self._http_client:
            await self._http_client.aclose()

    async def get_ip_info(self, ip: str) -> tuple[str | None, dict | None]:
        """Get FQDN and geolocation info for an IP."""
        fqdn = None
        geo_info = None

        # Get FQDN (sync operation, run in executor)
        try:
            loop = asyncio.get_event_loop()
            fqdn = await loop.run_in_executor(None, socket.getfqdn, ip)
        except Exception:
            pass

        # Get GeoIP info
        try:
            response = await self._http_client.get(
                f"http://ip-api.com/json/{ip}"
            )
            if response.status_code == 200:
                data = response.json()
                geo_info = {
                    "country": data.get("country"),
                    "region": data.get("regionName"),
                    "city": data.get("city"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "as": data.get("as"),
                }
        except Exception:
            pass

        return fqdn, geo_info

    async def check_dnsbl(self, ip: str, dnsbl: str, name: str) -> CheckResult:
        """Check a single DNSBL for an IP."""
        query = ".".join(reversed(ip.split("."))) + "." + dnsbl

        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.dns_timeout
            resolver.lifetime = self.dns_timeout

            # Run DNS query in executor (dnspython is sync)
            loop = asyncio.get_event_loop()

            def do_resolve():
                answers = resolver.resolve(query, "A")
                try:
                    txt_answers = resolver.resolve(query, "TXT")
                    txt_info = str(txt_answers[0])
                except Exception:
                    txt_info = None
                return str(answers[0]), txt_info

            a_record, txt_record = await loop.run_in_executor(None, do_resolve)

            details = f"{a_record}"
            if txt_record:
                details += f": {txt_record}"

            return CheckResult(
                source=name,
                source_type="dnsbl",
                listed=True,
                details=details,
            )

        except dns.resolver.NXDOMAIN:
            return CheckResult(
                source=name,
                source_type="dnsbl",
                listed=False,
            )
        except dns.resolver.Timeout:
            return CheckResult(
                source=name,
                source_type="dnsbl",
                listed=False,
                error="Timeout",
            )
        except dns.resolver.NoNameservers:
            return CheckResult(
                source=name,
                source_type="dnsbl",
                listed=False,
                error="No nameservers",
            )
        except dns.resolver.NoAnswer:
            return CheckResult(
                source=name,
                source_type="dnsbl",
                listed=False,
                error="No answer",
            )
        except Exception as e:
            return CheckResult(
                source=name,
                source_type="dnsbl",
                listed=False,
                error=str(e),
            )

    async def fetch_feed(self, url: str) -> set[str]:
        """Fetch and parse an HTTP threat feed."""
        if url in self._feed_cache:
            return self._feed_cache[url]

        try:
            response = await self._http_client.get(url)
            response.raise_for_status()
            content = response.text

            # Extract IPs from content
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            ips = set(re.findall(ip_pattern, content))

            self._feed_cache[url] = ips
            return ips
        except Exception:
            return set()

    async def check_http_feed(self, ip: str, feed: dict) -> CheckResult:
        """Check a single HTTP threat feed for an IP."""
        try:
            ips = await self.fetch_feed(feed["url"])
            listed = ip in ips

            return CheckResult(
                source=feed["name"],
                source_type="http_feed",
                listed=listed,
                details=feed["description"] if listed else None,
            )
        except Exception as e:
            return CheckResult(
                source=feed["name"],
                source_type="http_feed",
                listed=False,
                error=str(e),
            )

    async def check_ip(self, ip: str, include_info: bool = True) -> IPReport:
        """Check an IP against all blacklists."""
        report = IPReport(ip=ip)

        # Get IP info if requested
        if include_info:
            report.fqdn, report.geo_info = await self.get_ip_info(ip)

        # Create all check tasks
        tasks = []

        # DNSBL checks
        for dnsbl, name in DNSBLS:
            tasks.append(self.check_dnsbl(ip, dnsbl, name))

        # HTTP feed checks
        for feed in THREAT_FEEDS:
            tasks.append(self.check_http_feed(ip, feed))

        # Run all checks with concurrency limit
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def limited_task(task):
            async with semaphore:
                return await task

        results = await asyncio.gather(*[limited_task(t) for t in tasks])
        report.results = list(results)

        return report

    async def check_ips(self, ips: list[str], include_info: bool = True) -> list[IPReport]:
        """Check multiple IPs against all blacklists."""
        tasks = [self.check_ip(ip, include_info) for ip in ips]
        return await asyncio.gather(*tasks)

    def check_ip_sync(self, ip: str, include_info: bool = True) -> IPReport:
        """Synchronous wrapper for check_ip."""
        async def _run():
            async with IPChecker(
                timeout=self.timeout,
                dns_timeout=self.dns_timeout,
                max_concurrent=self.max_concurrent,
            ) as checker:
                return await checker.check_ip(ip, include_info)

        return asyncio.run(_run())

    def check_ips_sync(self, ips: list[str], include_info: bool = True) -> list[IPReport]:
        """Synchronous wrapper for check_ips."""
        async def _run():
            async with IPChecker(
                timeout=self.timeout,
                dns_timeout=self.dns_timeout,
                max_concurrent=self.max_concurrent,
            ) as checker:
                return await checker.check_ips(ips, include_info)

        return asyncio.run(_run())
