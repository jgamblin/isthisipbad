"""Configuration for threat intelligence sources."""

# DNS-based Blacklists (DNSBLs) - Updated December 2025
DNSBLS = [
    # Spamhaus - Most reliable and widely used
    ("zen.spamhaus.org", "Spamhaus ZEN (Combined)"),
    ("sbl.spamhaus.org", "Spamhaus SBL"),
    ("xbl.spamhaus.org", "Spamhaus XBL"),
    ("pbl.spamhaus.org", "Spamhaus PBL"),
    
    # SpamCop
    ("bl.spamcop.net", "SpamCop"),
    
    # Barracuda
    ("b.barracudacentral.org", "Barracuda"),
    
    # SORBS
    ("dnsbl.sorbs.net", "SORBS"),
    ("spam.dnsbl.sorbs.net", "SORBS Spam"),
    ("smtp.dnsbl.sorbs.net", "SORBS SMTP"),
    
    # Abuseat / CBL
    ("cbl.abuseat.org", "Abuseat CBL"),
    
    # UCEPROTECT
    ("dnsbl-1.uceprotect.net", "UCEPROTECT Level 1"),
    ("dnsbl-2.uceprotect.net", "UCEPROTECT Level 2"),
    
    # Other reliable DNSBLs
    ("psbl.surriel.com", "PSBL"),
    ("dnsbl.dronebl.org", "DroneRL"),
    ("bl.mailspike.net", "Mailspike"),
]

# HTTP-based Threat Intelligence Feeds - Updated December 2025
THREAT_FEEDS = [
    {
        "name": "EmergingThreats",
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "description": "Compromised IPs from Proofpoint",
    },
    {
        "name": "Blocklist.de",
        "url": "https://lists.blocklist.de/lists/all.txt",
        "description": "Brute force attackers",
    },
    {
        "name": "Feodo Tracker",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "description": "Banking trojans (Abuse.ch)",
    },
    {
        "name": "SSL Blacklist",
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
        "description": "Malicious SSL certificates (Abuse.ch)",
    },
    {
        "name": "TOR Exit Nodes",
        "url": "https://check.torproject.org/torbulkexitlist",
        "description": "TOR exit node list",
    },
    {
        "name": "CI Army",
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "description": "Malicious IPs",
    },
    {
        "name": "IPsum",
        "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
        "description": "High confidence threats (Level 3+)",
    },
    {
        "name": "Spamhaus DROP",
        "url": "https://www.spamhaus.org/drop/drop.txt",
        "description": "Don't Route Or Peer list",
    },
]
