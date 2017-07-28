import urllib2
import socket
from OTXv2 import OTXv2
from OTXv2 import OTXv2, IndicatorTypes

otx = OTXv2('API_KEY')

pulses = otx.getall()

for i in range(0,len(pulses)-1):
    print ("// https://otx.alienvault.com/pulse/" + pulses[i]["id"])
    indicators = pulses[i]["indicators"]
    for ind in indicators:
        if ind['type'] == "YARA":
            print(ind['content'])