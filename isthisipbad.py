#!/usr/bin/env python3
"""Is This IP Bad? - Check an IP against popular IP and DNS blacklists."""

import argparse
import os
import re
import socket
import sys
import urllib.error
import urllib.request
import warnings
from typing import Optional

import dns.resolver
import requests

warnings.filterwarnings("ignore", category=DeprecationWarning)


def color(text, color_code):
    if sys.platform == "win32" and os.getenv("TERM") != "xterm":
        return text

    return '\x1b[%dm%s\x1b[0m' % (color_code, text)


def red(text):
    return color(text, 31)


def blink(text):
    return color(text, 5)


def green(text):
    return color(text, 32)


def blue(text):
    return color(text, 34)


def content_test(url: str, badip: str) -> bool:
    """Check if an IP appears in a threat feed URL.
    
    Args:
        url: The URL of the threat feed to check
        badip: The IP address to look for
        
    Returns:
        True if IP is NOT found in the feed (good), False if found (bad) or error
    """
    try:
        request = urllib.request.Request(
            url,
            headers={'User-Agent': 'IsThisIPBad/1.0'}
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            html_content = response.read().decode('utf-8', errors='ignore')
            retcode = response.status

            if retcode == 200:
                matches = re.findall(re.escape(badip), html_content)
                return len(matches) == 0
            return False
    except urllib.error.URLError as e:
        print(blink(f'WARNING: Could not reach {url}: {e}'))
        return True  # Assume good if we can't check
    except Exception as e:
        print(blink(f'WARNING: Error checking {url}: {e}'))
        return True  # Assume good if we can't check

# DNS-based Blacklists (DNSBLs) - Updated December 2025
# Removed defunct services, kept reliable ones
DNSBLS = [
    # Spamhaus - Most reliable and widely used
    "zen.spamhaus.org",           # Combined: SBL+XBL+PBL
    "sbl.spamhaus.org",           # Spamhaus Block List
    "xbl.spamhaus.org",           # Exploits Block List
    "pbl.spamhaus.org",           # Policy Block List
    
    # SpamCop
    "bl.spamcop.net",
    
    # Barracuda
    "b.barracudacentral.org",
    
    # SORBS (Spam and Open Relay Blocking System)
    "dnsbl.sorbs.net",
    "spam.dnsbl.sorbs.net",
    "smtp.dnsbl.sorbs.net",
    
    # Abuseat / CBL
    "cbl.abuseat.org",
    
    # UCEPROTECT
    "dnsbl-1.uceprotect.net",
    "dnsbl-2.uceprotect.net",
    
    # Other reliable DNSBLs
    "psbl.surriel.com",
    "dnsbl.dronebl.org",
    "bl.mailspike.net",
]

# HTTP-based Threat Intelligence Feeds - Updated December 2025
# Removed defunct services (Dragon Research Group, NoThink, etc.)
THREAT_FEEDS = [
    # Emerging Threats (Proofpoint)
    ('https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
     'is not listed on EmergingThreats',
     'is listed on EmergingThreats',
     True),

    # Blocklist.de - Brute force attackers
    ('https://lists.blocklist.de/lists/all.txt',
     'is not listed on Blocklist.de',
     'is listed on Blocklist.de',
     True),

    # Abuse.ch Feodo Tracker - Banking trojans
    ('https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
     'is not listed on Feodo Tracker',
     'is listed on Feodo Tracker (Banking Trojan)',
     True),

    # Abuse.ch SSL Blacklist
    ('https://sslbl.abuse.ch/blacklist/sslipblacklist.txt',
     'is not listed on SSL Blacklist',
     'is listed on SSL Blacklist (Malicious SSL)',
     True),

    # TOR Exit Nodes (official Tor Project list)
    ('https://check.torproject.org/torbulkexitlist',
     'is not a TOR Exit Node',
     'is a TOR Exit Node',
     False),

    # CI Army - Malicious IPs
    ('https://cinsscore.com/list/ci-badguys.txt',
     'is not listed on CI Army',
     'is listed on CI Army',
     True),

    # IPsum - Daily updated threat intelligence
    ('https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt',
     'is not listed on IPsum (Level 3+)',
     'is listed on IPsum (High Confidence Threat)',
     True),

    # Spamhaus DROP (Don't Route Or Peer)
    ('https://www.spamhaus.org/drop/drop.txt',
     'is not listed on Spamhaus DROP',
     'is listed on Spamhaus DROP',
     True),
]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Is This IP Bad?')
    parser.add_argument('-i', '--ip', help='IP address to check')
    parser.add_argument('--success', help='Also display GOOD', required=False, action="store_true")
    args = parser.parse_args()

    if args is not None and args.ip is not None and len(args.ip) > 0:
        badip = args.ip
    else:
        try:
            my_ip = requests.get('https://api.ipify.org', timeout=10).text
        except requests.RequestException:
            my_ip = "Unable to determine"
        print(blue('Check IP against popular IP and DNS blacklists'))
        print(blue('A quick and dirty script by @jgamblin\n'))
        print(red(f'Your public IP address is {my_ip}\n'))

        # Get IP To Check
        resp = input('Would you like to check {0} ? (Y/N):'.format(my_ip))

        if resp.lower() in ["yes", "y"]:
            badip = my_ip
        else:
            badip = input(blue("\nWhat IP would you like to check?: "))
            if badip is None or badip == "":
                sys.exit("No IP address to check.")

    # IP INFO
    try:
        reversed_dns = socket.getfqdn(badip)
    except socket.error:
        reversed_dns = "Unable to resolve"
    
    try:
        geoip = requests.get(
            f'http://api.hackertarget.com/geoip/?q={badip}',
            timeout=10
        ).text
    except requests.RequestException:
        geoip = "Unable to fetch geolocation data"

    print(blue(f'\nThe FQDN for {badip} is {reversed_dns}\n'))
    print(red('Geolocation IP Information:'))
    print(blue(geoip))
    print()

    BAD = 0
    GOOD = 0

    print(blue('\nChecking HTTP-based threat feeds...'))
    for url, succ, fail, mal in THREAT_FEEDS:
        is_clean = content_test(url, badip)
        if is_clean:
            if args.success:
                print(green(f'{badip} {succ}'))
            GOOD += 1
        else:
            print(red(f'{badip} {fail}'))
            BAD += 1

    print(blue('\nChecking DNS-based blacklists...'))

    for bl in DNSBLS:
        try:
            my_resolver = dns.resolver.Resolver()
            query = '.'.join(reversed(str(badip).split("."))) + "." + bl
            my_resolver.timeout = 5
            my_resolver.lifetime = 5
            answers = my_resolver.resolve(query, "A")
            try:
                answer_txt = my_resolver.resolve(query, "TXT")
                txt_info = str(answer_txt[0])
            except Exception:
                txt_info = "No TXT record"
            print(red(f'{badip} is listed in {bl}') + f' ({answers[0]}: {txt_info})')
            BAD += 1

        except dns.resolver.NXDOMAIN:
            if args.success:
                print(green(f'{badip} is not listed in {bl}'))
            GOOD += 1

        except dns.resolver.Timeout:
            print(blink(f'WARNING: Timeout querying {bl}'))

        except dns.resolver.NoNameservers:
            print(blink(f'WARNING: No nameservers for {bl}'))

        except dns.resolver.NoAnswer:
            print(blink(f'WARNING: No answer for {bl}'))

    print(red(f'\n{badip} is on {BAD}/{GOOD+BAD} blacklists.\n'))