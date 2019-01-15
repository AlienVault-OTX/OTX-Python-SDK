[![Build Status](https://travis-ci.org/AlienVault-Labs/OTX-Python-SDK.svg)](https://travis-ci.org/AlienVault-Labs/OTX-Python-SDK)
# About
Open Threat Exchange is an open community that allows participants to learn about the latest threats, research indicators of compromise observed in their environments, share threats they have identified, and automatically update their security infrastructure with the latest indicators to defend their environment.

OTX Direct Connect agents provide a way to automatically update your security infrastructure with pulses you have subscribed to from with Open Threat Exchange. By using Direct Connect, the indicators contained within the pulses you have subscribed to can be downloaded and made locally available for other applications such as Intrusion Detection Systems, Firewalls, and other security-focused applications.

OTX Direct Connect provides a mechanism to automatically pull indicators of compromise from the Open Threat Exchange portal into your environment.  The DirectConnect API provides access to all _Pulses_ that you have subscribed to in Open Threat Exchange (https://otx.alienvault.com).

# Installation
You can install with ``` pip install OTXv2 ``` or alternatively:

1. Clone this repo
2. Run (from the root directory)   ``` pip install . ```   or ``` python setup.py install ```
3. Integrate into your codebase (see Python Notebook example below)

For more information about the particular API calls see  https://otx.alienvault.com/api (Endpoint details on 'docs' tab)

# Installation with Python Notebook
1. Clone this repo
2. Install pandas 

``` pip install pandas```

2. Install python notebook (http://jupyter.readthedocs.org/en/latest/install.html) 

``` pip install jupyter ```

3. Run notebook

```jupyter notebook howto_use_python_otx_api.ipynb```
 
# Example

Reading contents from OTX:
```
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
otx = OTXv2("API_KEY")
# Get all the indicators associated with a pulse
indicators = otx.get_pulse_indicators("pulse_id")
for indicator in indicators:
    print indicator["indicator"] + indicator["type"]
# Get everything OTX knows about google.com
otx.get_indicator_details_full(IndicatorTypes.DOMAIN, "google.com")
```
Adding content to OTX:
```
from OTXv2 import OTXv2
otx = OTXv2("API_KEY")
name = 'Test Pulse'
indicators = [
    {'indicator': '69.73.130.198', 'type': 'IPv4'},
    {'indicator': 'aoldaily.com', 'type': 'Domain'}
]
response = otx.create_pulse(name=name ,public=True ,indicators=indicators ,tags=[] , references=[])
print str(response)
```

Additional Examples:
- Simple command line interface to OTX - https://github.com/AlienVault-OTX/OTX-Python-SDK/blob/master/examples/cli_example.py
- Use OTX to determine if files, domains, IPs or URLs are malicious - https://github.com/AlienVault-OTX/OTX-Python-SDK/blob/master/examples/is_malicious/is_malicious.py
- Store all the indicators from pulses you are subscribed to in a CSV file - https://github.com/Neo23x0/signature-base/blob/master/threatintel/get-otx-iocs.py
- Maintain a feed of indicators in a pulse for users - https://github.com/AlienVault-OTX/OTX-Python-SDK/blob/master/examples/update_feed.py
- Adding domains to an existing pulse - https://github.com/AlienVault-OTX/OTX-Python-SDK/blob/master/examples/PulseManager.py

More examples are at https://otx.alienvault.com/api/
