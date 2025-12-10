"""Tests for the IP checker."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from datetime import datetime

from isthisipbad.checker import (
    IPChecker,
    CheckResult,
    IPReport,
    ThreatLevel,
)
from isthisipbad.config import DNSBLS, THREAT_FEEDS


class TestCheckResult:
    """Tests for CheckResult dataclass."""
    
    def test_create_listed_result(self):
        result = CheckResult(
            source="TestBL",
            source_type="dnsbl",
            listed=True,
            details="127.0.0.2",
        )
        assert result.source == "TestBL"
        assert result.listed is True
        assert result.error is None
    
    def test_create_clean_result(self):
        result = CheckResult(
            source="TestBL",
            source_type="dnsbl",
            listed=False,
        )
        assert result.listed is False
    
    def test_create_error_result(self):
        result = CheckResult(
            source="TestBL",
            source_type="dnsbl",
            listed=False,
            error="Timeout",
        )
        assert result.error == "Timeout"
    
    def test_to_dict(self):
        result = CheckResult(
            source="TestBL",
            source_type="dnsbl",
            listed=True,
            details="127.0.0.2",
        )
        d = result.to_dict()
        assert d["source"] == "TestBL"
        assert d["listed"] is True
        assert "timestamp" in d


class TestIPReport:
    """Tests for IPReport dataclass."""
    
    def test_empty_report(self):
        report = IPReport(ip="8.8.8.8")
        assert report.ip == "8.8.8.8"
        assert report.total_checks == 0
        assert report.blacklist_count == 0
        assert report.threat_level == ThreatLevel.CLEAN
    
    def test_report_with_results(self):
        results = [
            CheckResult("BL1", "dnsbl", listed=True),
            CheckResult("BL2", "dnsbl", listed=False),
            CheckResult("BL3", "dnsbl", listed=True),
            CheckResult("Feed1", "http_feed", listed=False),
        ]
        report = IPReport(ip="1.2.3.4", results=results)
        
        assert report.total_checks == 4
        assert report.blacklist_count == 2
        assert report.clean_count == 2
    
    def test_report_with_errors(self):
        results = [
            CheckResult("BL1", "dnsbl", listed=False, error="Timeout"),
            CheckResult("BL2", "dnsbl", listed=False),
        ]
        report = IPReport(ip="1.2.3.4", results=results)
        
        assert report.total_checks == 1  # Excludes errors
        assert report.error_count == 1
    
    def test_threat_level_clean(self):
        results = [
            CheckResult("BL1", "dnsbl", listed=False),
            CheckResult("BL2", "dnsbl", listed=False),
        ]
        report = IPReport(ip="8.8.8.8", results=results)
        assert report.threat_level == ThreatLevel.CLEAN
    
    def test_threat_level_low(self):
        results = [
            CheckResult("BL1", "dnsbl", listed=True),
            CheckResult("BL2", "dnsbl", listed=False),
            CheckResult("BL3", "dnsbl", listed=False),
            CheckResult("BL4", "dnsbl", listed=False),
        ] * 5  # 5 listed out of 20
        results[0] = CheckResult("BL1", "dnsbl", listed=True)
        report = IPReport(ip="1.2.3.4", results=results[:20])
        # 1 listed out of 20 = LOW
        report_low = IPReport(ip="1.2.3.4", results=[
            CheckResult("BL1", "dnsbl", listed=True),
            *[CheckResult(f"BL{i}", "dnsbl", listed=False) for i in range(2, 20)]
        ])
        assert report_low.threat_level == ThreatLevel.LOW
    
    def test_threat_level_critical(self):
        results = [CheckResult(f"BL{i}", "dnsbl", listed=True) for i in range(15)]
        report = IPReport(ip="1.2.3.4", results=results)
        assert report.threat_level == ThreatLevel.CRITICAL
    
    def test_to_dict(self):
        report = IPReport(
            ip="8.8.8.8",
            fqdn="dns.google",
            geo_info={"country": "US"},
            results=[CheckResult("BL1", "dnsbl", listed=False)],
        )
        d = report.to_dict()
        
        assert d["ip"] == "8.8.8.8"
        assert d["fqdn"] == "dns.google"
        assert d["geo_info"]["country"] == "US"
        assert "summary" in d
        assert d["summary"]["threat_level"] == "clean"


class TestThreatLevel:
    """Tests for ThreatLevel enum."""
    
    def test_values(self):
        assert ThreatLevel.CLEAN.value == "clean"
        assert ThreatLevel.LOW.value == "low"
        assert ThreatLevel.MEDIUM.value == "medium"
        assert ThreatLevel.HIGH.value == "high"
        assert ThreatLevel.CRITICAL.value == "critical"


class TestConfig:
    """Tests for configuration."""
    
    def test_dnsbls_not_empty(self):
        assert len(DNSBLS) > 0
    
    def test_dnsbls_format(self):
        for dnsbl, name in DNSBLS:
            assert isinstance(dnsbl, str)
            assert isinstance(name, str)
            assert "." in dnsbl  # Should be a domain
    
    def test_threat_feeds_not_empty(self):
        assert len(THREAT_FEEDS) > 0
    
    def test_threat_feeds_format(self):
        for feed in THREAT_FEEDS:
            assert "name" in feed
            assert "url" in feed
            assert "description" in feed
            assert feed["url"].startswith("http")


@pytest.mark.asyncio
class TestIPCheckerAsync:
    """Async tests for IPChecker."""
    
    async def test_checker_context_manager(self):
        async with IPChecker() as checker:
            assert checker._http_client is not None
    
    @patch("dns.resolver.Resolver")
    async def test_check_dnsbl_listed(self, mock_resolver_class):
        """Test DNSBL check when IP is listed."""
        mock_resolver = MagicMock()
        mock_resolver_class.return_value = mock_resolver
        
        # Mock the resolve method to return a result (IP is listed)
        mock_answer = MagicMock()
        mock_answer.__str__ = lambda self: "127.0.0.2"
        mock_resolver.resolve.return_value = [mock_answer]
        
        async with IPChecker() as checker:
            result = await checker.check_dnsbl("1.2.3.4", "test.dnsbl.org", "Test DNSBL")
        
        assert result.listed is True
        assert result.source == "Test DNSBL"
    
    @patch("dns.resolver.Resolver")
    async def test_check_dnsbl_not_listed(self, mock_resolver_class):
        """Test DNSBL check when IP is not listed."""
        import dns.resolver
        
        mock_resolver = MagicMock()
        mock_resolver_class.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()
        
        async with IPChecker() as checker:
            result = await checker.check_dnsbl("8.8.8.8", "test.dnsbl.org", "Test DNSBL")
        
        assert result.listed is False
        assert result.error is None
    
    @patch("dns.resolver.Resolver")
    async def test_check_dnsbl_timeout(self, mock_resolver_class):
        """Test DNSBL check on timeout."""
        import dns.resolver
        
        mock_resolver = MagicMock()
        mock_resolver_class.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.Timeout()
        
        async with IPChecker() as checker:
            result = await checker.check_dnsbl("8.8.8.8", "test.dnsbl.org", "Test DNSBL")
        
        assert result.listed is False
        assert result.error == "Timeout"


class TestIPCheckerSync:
    """Synchronous tests for IPChecker."""
    
    def test_sync_wrapper_exists(self):
        checker = IPChecker()
        assert hasattr(checker, "check_ip_sync")
        assert hasattr(checker, "check_ips_sync")
