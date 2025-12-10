"""Is This IP Bad? - Check an IP against popular IP and DNS blacklists."""

__version__ = "2.0.0"
__author__ = "Jerry Gamblin"

from .checker import IPChecker, CheckResult, ThreatLevel
from .config import DNSBLS, THREAT_FEEDS

__all__ = ["IPChecker", "CheckResult", "ThreatLevel", "DNSBLS", "THREAT_FEEDS"]
