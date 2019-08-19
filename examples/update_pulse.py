#!/usr/bin/env python

#  Simple example that prints the indicators from a pulse, then replaces them
import json
import os
from OTXv2 import OTXv2


# store OTX API key in environment variable OTX_API_KEY
API_KEY = os.getenv("OTX_API_KEY")

pulse_id = ''

otx = OTXv2(API_KEY)

print('Getting indicators for pulse:')
indicators = otx.get_pulse_indicators(pulse_id=pulse_id)
for indicator in indicators:
    print(indicator['indicator'] + ',' + indicator['type'] + ',' + str(indicator['id']))

print('Updating indicators for pulse:')
with open('updatePulse.json') as data_file:
    data = json.load(data_file)
    response = otx.replace_pulse_indicators(pulse_id, data)
    print('Response: ' + str(response))
