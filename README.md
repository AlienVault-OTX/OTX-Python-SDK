# OTX-Python-SDK
Open Threat Exchange is an open community that allows participants to learn about the latest threats, research indicators of compromise observed in their environments, share threats they have identified, and automatically update their security infrastructure with the latest indicators to defend their environment.

OTX Direct Connect agents provide a way to automatically update your security infrastructure with pulses you have subscribed to from with Open Threat Exchange. By using Direct Connect, the indicators contained within the pulses you have subscribed to can be downloaded and made locally available for other applications such as Intrusion Detection Systems, Firewalls, and other security-focused applications.


# OTX DirectConnect Python SDK
OTX DirectConnect provides a mechanism to automatically pull indicators of compromise from the Open Threat Exchange portal into your environment.  The DirectConnect API provides access to all _Pulses_ that you have subscribed to in Open Threat Exchange (https://otx.alienvault.com).

1. Clone this repo
2. Run (from the root directory)   ``` pip install . ```   or ``` python setup.py install ```
3. Integrate into your codebase (see Python Notebook example below)


## Installation and Python Notebook Usage
1. Clone this repo
2. Install pandas 

``` pip install pandas```

2. Install python notebook (http://jupyter.readthedocs.org/en/latest/install.html) 

``` pip install jupyter ```

3. Run notebook

```jupyter notebook howto_use_python_otx_api.ipynb```

