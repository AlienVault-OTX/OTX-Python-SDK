# This example:
# 1) Takes a MISP Json representing malicious activity, eg; those at https://www.circl.lu/doc/misp/feed-osint/ then
# 2) Creates an OTX pulse representing that data


from OTXv2 import OTXv2, InvalidAPIKey, BadRequest, RetryError
import IndicatorTypes
import requests, json

# SETTINGS
# Your API key
API_KEY = ''
# Example feed source
misp_json_url = 'https://www.circl.lu/doc/misp/feed-osint/58539031-aa78-4da1-9289-487102de0b81.json'

OTX_SERVER = 'https://otx.alienvault.com/'
otx = OTXv2(API_KEY, server=OTX_SERVER)

result =  requests.get(misp_json_url)
j = json.loads(result.text)

title = j['Event']['info']
tags = []
indicator_list = []
reference_list = [ misp_json_url ]
tlp = 'white'

for attribute in j['Event']['Attribute']:

    if attribute['to_ids']:

        indicator_title = ''
        indicator_description = ''
        if 'category' in attribute:
            indicator_title = attribute['category']
        if 'comment' in attribute:
            indicator_description += attribute['comment']

        if attribute['type'] == 'md5':
            indicator_list.append({'indicator': attribute['value'], 'type': IndicatorTypes.FILE_HASH_MD5.name, 'title': indicator_title, 'description': indicator_description})
        if attribute['type'] == 'sha1':
            indicator_list.append({'indicator': attribute['value'], 'type': IndicatorTypes.FILE_HASH_MD5.name, 'title': indicator_title, 'description': indicator_description})
        if attribute['type'] == 'sha256':
            indicator_list.append({'indicator': attribute['value'], 'type': IndicatorTypes.FILE_HASH_MD5.name, 'title': indicator_title, 'description': indicator_description})
        if attribute['type'] == 'hostname':
            indicator_list.append({'indicator': attribute['value'], 'type': IndicatorTypes.HOSTNAME.name, 'title': indicator_title, 'description': indicator_description})
        if attribute['type'] == 'domain':
            indicator_list.append({'indicator': attribute['value'], 'type': IndicatorTypes.DOMAIN.name, 'title': indicator_title, 'description': indicator_description})
        if attribute['type'] == 'ip-src':
            indicator_list.append({'indicator': attribute['value'], 'type': IndicatorTypes.IPv4.name, 'title': indicator_title, 'description': indicator_description})
        if attribute['type'] == 'ip-dst':
            indicator_list.append({'indicator': attribute['value'], 'type': IndicatorTypes.IPv4.name, 'title': indicator_title, 'description': indicator_description})
        if attribute['type'] == 'whois-registrant-email':
            indicator_list.append({'indicator': attribute['value'], 'type': IndicatorTypes.EMAIL.name, 'title': indicator_title, 'description': indicator_description})

    if attribute['type'] == 'link':
            reference_list.append(attribute['value'])

for tag in j['Event']['Tag']:
    name = tag['name']
    if 'tlp:' in name:
        tlp = name.split('tlp:')[1]

    if 'threat-actor=' in name:
        adversary = name.split('threat-actor=')[1].replace('"','').replace('\\','')
        # I need to improve the sdk to set the adversary properly here
        tags = [ adversary ]

response = otx.create_pulse(name=title, indicators=indicator_list, references=reference_list, tlp=tlp, description="Pulse imported from MISP", tags = tags)

print ("Made pulse with response: " + str(response))
