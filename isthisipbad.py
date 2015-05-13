#!/usr/bin/env python
# Name:     isthisipbad.py
# Purpose:  Checka IP against popular IP blacklist
# By:       Jerry Gamblin
# Date:     11.05.15
# Modified  11.05.15
# Rev Level 0.5
# -----------------------------------------------

import os
import sys
import json
import urllib
import urllib2
import hashlib
import argparse
import re
import socket
import dns.resolver
from urllib2 import urlopen


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


def content_test(url, badip):
    """ 
    Test the content of url's response to see if it contains badip.

        Args:
            url -- the URL to request data from
            badip -- the IP address in question

        Returns:
            Boolean
    """

    try:
        request = urllib2.Request(url)
        request.add_header('User-Agent', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.153 Safari/537.36')
        html_content = urllib2.build_opener().open(request).read()

        matches = re.findall(badip, html_content)

        return len(matches) == 0
    except Exception, e:
        print "Error! %s" % e
        return False

bls = ["b.barracudacentral.org", "bl.deadbeef.com", "bl.emailbasura.org", "bl.spamcannibal.org", "bl.spamcop.net", "blackholes.five-ten-sg.com", "blacklist.woody.ch", "bogons.cymru.com", "cbl.abuseat.org", "cdl.anti-spam.org.cn", "combined.abuse.ch", "combined.rbl.msrbl.net", "db.wpbl.info", "dnsbl-1.uceprotect.net", "dnsbl-2.uceprotect.net", "dnsbl-3.uceprotect.net", "dnsbl.cyberlogic.net", "dnsbl.inps.de", "dnsbl.sorbs.net", "drone.abuse.ch", "drone.abuse.ch", "duinv.aupads.org", "dul.dnsbl.sorbs.net", "dul.ru,dyna.spamrats.com", "dynip.rothen.com", "http.dnsbl.sorbs.net", "images.rbl.msrbl.net", "ips.backscatterer.org", "ix.dnsbl.manitu.net", "korea.services.net", "misc.dnsbl.sorbs.net", "noptr.spamrats.com", "ohps.dnsbl.net.au", "omrs.dnsbl.net.au", "orvedb.aupads.org", "osps.dnsbl.net.au", "osrs.dnsbl.net.au", "owfs.dnsbl.net.au", "owps.dnsbl.net.au,pbl.spamhaus.org", "phishing.rbl.msrbl.net", "probes.dnsbl.net.au", "proxy.bl.gweep.ca", "proxy.block.transip.nl", "psbl.surriel.com", "rbl.interserver.net", "rdts.dnsbl.net.au", "relays.bl.gweep.ca", "relays.bl.kundenserver.de", "relays.nether.net", "residential.block.transip.nl", "ricn.dnsbl.net.au", "rmst.dnsbl.net.au", "sbl.spamhaus.org,short.rbl.jp,smtp.dnsbl.sorbs.net", "socks.dnsbl.sorbs.net", "spam.abuse.ch", "spam.dnsbl.sorbs.net,spam.rbl.msrbl.net", "spam.spamrats.com", "spamlist.or.kr", "spamrbl.imp.ch", "t3direct.dnsbl.net.au", "tor.dnsbl.sectoor.de", "torserver.tor.dnsbl.sectoor.de", "ubl.lashback.com", "ubl.unsubscore.com", "virbl.bit.nl", "virus.rbl.jp", "virus.rbl.msrbl.net", "web.dnsbl.sorbs.net", "wormrbl.imp.ch", "xbl.spamhaus.org", "zen.spamhaus.org", "zombie.dnsbl.sorbs.net"]

URLS = [
    #TOR
    ('http://torstatus.blutmagie.de/ip_list_exit.php/Tor_ip_list_EXIT.csv',
     'is not a TOR Exit Node',
     'is a TOR Exit Node',
     False),

    #EmergingThreats
    ('http://rules.emergingthreats.net/blockrules/compromised-ips.txt',
     'is not listed on EmergingThreats',
     'is listed on EmergingThreats',
     True),

    #AlienVault
   ('http://reputation.alienvault.com/reputation.data',
    'is not listed on AlienVault',
    'is listed on AlienVault',
    True),

    #BlocklistDE
    ('http://www.blocklist.de/lists/bruteforcelogin.txt',
     'is not listed on BlocklistDE',
     'is listed on BlocklistDE',
     True),

    #Dragon Research Group - SSH
    ('http://dragonresearchgroup.org/insight/sshpwauth.txt',
     'is not listed on Dragon Research Group - SSH',
     'is listed on Dragon Research Group - SSH',
     True),

    #Dragon Research Group - VNC
    ('http://dragonresearchgroup.org/insight/vncprobe.txt',
     'is not listed on Dragon Research Group - VNC',
     'is listed on Dragon Research Group - VNC',
     True),

    #OpenBLock
    ('http://www.openbl.org/lists/date_all.txt',
     'is not listed on OpenBlock',
     'is listed on OpenBlock',
     True),

    #NoThinkMalware
    ('http://www.nothink.org/blacklist/blacklist_malware_http.txt',
     'is not listed on NoThink Malware',
     'is listed on NoThink Malware',
     True),
     
    #NoThinkSSH
    ('http://www.nothink.org/blacklist/blacklist_ssh_all.txt',
     'is not listed on NoThink SSH',
     'is listed on NoThink SSH',
     True),

    #Feodo
    ('http://rules.emergingthreats.net/blockrules/compromised-ips.txt',
     'is not listed on Feodo',
     'is listed on Feodo',
     True),

    #antispam.imp.ch
    ('http://antispam.imp.ch/spamlist',
     'is not listed on antispam.imp.ch',
     'is listed on antispam.imp.ch',
     True),

    #dshield
    ('http://www.dshield.org/ipsascii.html?limit=10000',
     'is not listed on dshield',
     'is listed on dshield',
     True),

    #malc0de
    ('http://malc0de.com/bl/IP_Blacklist.txt',
     'is not listed on malc0de',
     'is listed on malc0de',
     True),

    #MalWareBytes
    ('http://hosts-file.net/rss.asp',
     'is not listed on MalWareBytes',
     'is listed on MalWareBytes',
     True)]


if __name__ == "__main__":

    my_ip = urlopen('http://icanhazip.com').read()

    print(blue('Check IP against popular IP and DNS blacklist'))
    print(blue('A quick and dirty script by @jgamblin'))
    print('\n')
    print(red('Your public IP address is {0}'.format(my_ip)))
    print('\n')

    #Get IP To SCAN

    resp = raw_input('Would you like to check {0}? (Y/N):'.format(my_ip))

    if resp.lower() in ["yes", "y"]:
        badip = my_ip
    else:
        badip = raw_input(blue("What IP would you like to check?: "))

    print('\n')

    #IP INFO
    reversed_dns = socket.getfqdn(badip)
    geoip = urllib.urlopen('http://api.hackertarget.com/geoip/?q=' + badip).read()

    print(blue('The FQDN for {0} is {1}'.format(badip, reversed_dns)))
    print('\n')
    print(red('Some GEOIP Information:'))
    print(blue(geoip))
    print('\n')


    BAD = 0
    GOOD = 0

    for url, succ, fail, mal in URLS:
        if content_test(url, badip):
            print(green('{0} {1}'.format(badip, succ)))
            GOOD = GOOD + 1
        else:
            BAD = BAD + 1

            print(red('{0} {1}'.format(badip, fail)))

    BAD = BAD
    GOOD = GOOD   

    for bl in bls:
        try:
                my_resolver = dns.resolver.Resolver()
                query = '.'.join(reversed(str(badip).split("."))) + "." + bl
		my_resolver.timeout = 5
		my_resolver.lifetime = 5
                answers = my_resolver.query(query, "A")
                answer_txt = my_resolver.query(query, "TXT")
                print 'URL: %s IS listed in %s (%s: %s)' %(url, bl, answers[0], answer_txt[0])
		BAD = BAD + 1
            
        except dns.resolver.NXDOMAIN: 
            print (green(badip + ' is not listed on ' + bl))
	    GOOD = GOOD + 1
            
           
#This Doesnt work because I am stupid. 
print('\n')
print(red('{0} is on {1}/{2} lists.'.format(badip, BAD, (GOOD+BAD))))
print('\n')
