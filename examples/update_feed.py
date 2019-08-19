#!/usr/bin/env python

# Simple example that keeps a pulse up to date with a feed
# - If new indicators appear - they will be added
# - If indicators are removed from a feed - they will be set to expire (currently this can take up to an hour, but will decrease shortly)
#
# To create a pulse with a description etc.:
# 1) Create a new pulse within the web interface with the title, description etc. of your choosing
# 2) Set the pulse pulse_id of your pulse below and run the script
# Example pulse created with this script: https://otx.alienvault.com/pulse/58bd6a67f6a7974d31a1138d/

import os
from OTXv2 import OTXv2
import socket
import urllib2

# Your API key - set in environment variable named OTX_API_KEY
API_KEY = os.getenv('OTX_API_KEY')

# Create a pulse and set below, the pulse_id is in the url when using OTX eg; https://otx.alienvault.com/pulse/PULSE_ID/
pulse_id = ''

# Example feed source
feed_url = 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt'
otx = OTXv2(API_KEY)

def valid_ip(ip, otx):
    try:
        # Confirm valid IP, exception if not
        socket.inet_aton(ip)
        return True
    except Exception as e:
        print(str(e))
        return False

# Here we download and parse the feed
print('Downloading feed from ' + feed_url)
new_indicators = []
data = urllib2.urlopen(feed_url)
for line in data.readlines():
    if not line.startswith('#'):
        ip = line.strip()
        # Is it a valid IP?
        if valid_ip(ip, otx):
            print('Will add ' + ip)
            # Change this to type : "Domain" for a domain indicator etc.
            new_indicators.append({ 'indicator': ip, 'type': 'IPv4' })
        else:
            print('Wont add ' + ip)

print('Updating indicators')
response = otx.replace_pulse_indicators(pulse_id, new_indicators)
print('Completed updating pulse')
