#!/usr/bin/env python

from OTXv2 import OTXv2Cached, IndicatorTypes
import logging
import os

logging.basicConfig(level=logging.INFO)


# store OTX API key in environment variable OTX_API_KEY
API_KEY = os.getenv("OTX_API_KEY")

# OTXv2Cached is a class like OTXv2 except that it maintains a local cache and therefore does not
# need to constantly fetch all the data from the server
# Initial fetch may take some time, subsequent fetches should be much faster (and easier on our servers)
otx = OTXv2Cached(API_KEY)

# update local cache by fetching new pulses, or fetching pulses that you need due to changes in your subscription
otx.update()

pulses = otx.getall()

for i in otx.get_all_indicators(indicator_types=[IndicatorTypes.YARA]):
    print(i['content'])
