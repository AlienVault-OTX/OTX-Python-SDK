# Simple example that keeps a pulse up to date with a feed
# Feed source and details: https://feodotracker.abuse.ch/

from OTXv2 import OTXv2
import urllib2
import socket
import IndicatorTypes

# Your API key
API_KEY = ''
# The id of the pulse we will be replacing the indicators of, eg; https://otx.alienvault.com/pulse/PULSE_ID/
pulse_id= ''
OTX_SERVER = 'https://otx.alienvault.com/'
feed_url = 'https://feodotracker.abuse.ch/blocklist/?download=ipblocklist'

otx = OTXv2(API_KEY, server=OTX_SERVER)

def valid_ip(ip, otx):
    try:
        # Confirm valid IP, exception if not
        socket.inet_aton(ip)
        # Also use OTX's built in validation
        response = otx.validate_indicator(IndicatorTypes.IPv4, ip, '')
        if response['status'] !='success':
            return False
        # Check the IP isn't whitelisted by OTX, eg; 8.8.8.8
        response = otx.get_indicator_details_full(IndicatorTypes.IPv4, ip)
        if 'general' in response:
            if 'validation' in response['general']:
                if ['source'] in response['general']['validation']:
                    if response['general']['validation']['source'] == 'whitelist':
                        return False
        return True
    except Exception as e:
        print str(e)
        return False

print 'Downloading feed from ' + feed_url
new_indicators = []
data = urllib2.urlopen(feed_url)
for line in data.readlines():
        if not line.startswith('#'):
            ip = line.strip()
            if valid_ip(ip, otx):
                print 'Will add ' + ip
                new_indicators.append({ 'indicator': ip, 'type': 'IPv4' })
            else:
                print 'Wont add ' + ip

print 'Updating indicators'
response = otx.replace_pulse_indicators(pulse_id, new_indicators)
print 'Complete'