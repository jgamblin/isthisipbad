
#!/usr/bin/env python
# Name:     isthisipbad.py
# Purpose:  Checka IP against popular IP blacklist
# By:       Jerry Gamblin
# Date:     10.05.15
# Modified  10.05.15
# Rev Level 0.1
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

def color(text, color_code):
    if sys.platform == "win32" and os.getenv("TERM") != "xterm":
        return text
 
    return '\x1b[%dm%s\x1b[0m' % (color_code, text)
 
def red(text):
    return color(text, 31)
 
def blink(text):
    return color(text, 05)
    
def Green(text):
    return color(text, 32)
 
def yellow(text):
    return color(text, 34)

from urllib2 import urlopen
my_ip = urlopen('http://ip.42.pl/raw').read()

print(yellow('Check IP addresses against popular IP blacklist'))
print(yellow('A quick and dirty script by @jgamblin'))
print('\n')
print(red('Your public IP address is ' + my_ip))
print('\n')

#Get IP To SCAN

Join = raw_input('Would you like to check ' + my_ip + '? (Y/N):') 

if Join == "yes":
	badip = my_ip
	

elif Join == "YES":
	badip = my_ip
	

elif Join == "Y":
	badip = my_ip
	

elif Join == "y":
	badip = my_ip
	
	
else:
	badip = raw_input (yellow("What IP would you like to check?: "))
	
print ('\n')

#IP INFO
reversed_dns = socket.getfqdn(badip)
print ('\n')
print (yellow('The FQDN for ' + badip + ' is ' + reversed_dns))
print ('\n')


BAD = 0

#TOR
html_content = urllib2.urlopen('http://torstatus.blutmagie.de/ip_list_exit.php/Tor_ip_list_EXIT.csv').read()

matches = re.findall(badip, html_content);

if len(matches) == 0: 
   print (Green(badip + ' is not a TOR Exit Node'))
else:
    print (red(badip + ' is a TOR Exit Node'))

#EmergingThreats
html_content = urllib2.urlopen('http://rules.emergingthreats.net/blockrules/compromised-ips.txt').read()

matches = re.findall(badip, html_content);

if len(matches) == 0: 
   print (Green(badip + ' is not listed on EmergingThreats'))
else:
    print (red(badip + ' is listed on EmergingThreats'))
    BAD = BAD + 1

#AlienVault
html_content = urllib2.urlopen('http://reputation.alienvault.com/reputation.data').read()

matches = re.findall(badip, html_content);

if len(matches) == 0: 
  print (Green(badip + ' is not listed on AlienVault'))
else:
    print (red(badip + ' is listed on AlienVault'))
    BAD = BAD + 1

#BlocklistDE
html_content = urllib2.urlopen('http://www.blocklist.de/lists/bruteforcelogin.txt').read()

matches = re.findall(badip, html_content);

if len(matches) == 0: 
   print (Green(badip + ' is not listed on BlocklistDE'))
else:
    print (red(badip + ' is listed on BlocklistDE'))
    BAD = BAD + 1

#Dragon Research Group - SSH
html_content = urllib2.urlopen('http://dragonresearchgroup.org/insight/sshpwauth.txt').read()

matches = re.findall(badip, html_content);

if len(matches) == 0: 
   print (Green(badip + ' is not listed on Dragon Research Group - SSH'))
else:
    print (red(badip + ' is listed on Dragon Research Group - SSH'))
    BAD = BAD + 1

#Dragon Research Group - VNC
html_content = urllib2.urlopen('http://dragonresearchgroup.org/insight/vncprobe.txt').read()

matches = re.findall(badip, html_content);

if len(matches) == 0: 
   print (Green(badip + ' is not listed on Dragon Research Group - VNC'))
else:
    print (red(badip + ' is listed on Dragon Research Group - VNC'))
    BAD = BAD + 1

#OpenBLock
html_content = urllib2.urlopen('http://www.openbl.org/lists/date_all.txt').read()

matches = re.findall(badip, html_content);

if len(matches) == 0: 
   print (Green(badip + ' is not listed on OpenBlock'))
else:
    print (red(badip + ' is listed on OpenBlock'))
    BAD = BAD + 1

#NoThink
html_content = urllib2.urlopen('http://www.nothink.org/blacklist/blacklist_malware_http.txt').read()

matches = re.findall(badip, html_content);

if len(matches) == 0: 
   print (Green(badip + ' is not listed on NoThink'))
else:
    print (red(badip + ' is listed on NoThink'))
    BAD = BAD + 1

#Feodo
html_content = urllib2.urlopen('http://rules.emergingthreats.net/blockrules/compromised-ips.txt').read()

matches = re.findall(badip, html_content);

if len(matches) == 0: 
   print (Green(badip + ' is not listed on Feodo'))
else:
    print (red(badip + ' is listed on Feodo'))
    BAD = BAD + 1

#antispam.imp.ch
html_content = urllib2.urlopen('http://antispam.imp.ch/spamlist').read()

matches = re.findall(badip, html_content);

if len(matches) == 0: 
   print (Green(badip + ' is not listed on antispam.imp.ch'))
else:
    print (red(badip + ' is listed on antispam.imp.ch'))
    BAD = BAD + 1

#dshield
html_content = urllib2.urlopen('http://www.dshield.org/ipsascii.html').read()

matches = re.findall(badip, html_content);

if len(matches) == 0: 
   print (Green(badip + ' is not listed on dshield'))
else:
    print (red(badip + ' is listed on dshield'))
    BAD = BAD + 1

#malc0de
html_content = urllib2.urlopen('http://malc0de.com/bl/IP_Blacklist.txt').read()

matches = re.findall(badip, html_content);

if len(matches) == 0: 
   print (Green(badip + ' is not listed on malc0de'))
else:
    print (red(badip + ' is listed on malc0de'))
    BAD = BAD + 1

#MalWareBytes
html_content = urllib2.urlopen('http://hosts-file.net/rss.asp').read()

matches = re.findall(badip, html_content);

if len(matches) == 0: 
   print (Green(badip + ' is not listed on MalWareBytes'))
else:
    print (red(badip + ' is listed on MalWareBytes'))
    BAD = BAD + 1

print('\n')
print (red (badip + ' is on %0.f lists.')) % BAD
