# Simple example that prints the indicators from a pulse, then replaces them
from OTXv2 import OTXv2
import json

API_KEY = ''
pulse_id= ''
OTX_SERVER = 'https://otx.alienvault.com'

otx = OTXv2(API_KEY, server=OTX_SERVER)

print 'Getting indicators for pulse:'
indicators = otx.get_pulse_indicators(pulse_id=pulse_id)
for indicator in indicators:
    print indicator['indicator'] + ',' + indicator['type'] + ',' + str(indicator['id'])

print 'Updating indicators for pulse:'
with open('updatePulse.json') as data_file:
    data = json.load(data_file)
    response = otx.replace_pulse_indicators(pulse_id, data)
    print 'Response: ' + str(response)
