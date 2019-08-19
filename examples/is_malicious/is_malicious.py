#!/usr/bin/env python
#  This script tells if a File, IP, Domain or URL may be malicious according to the data in OTX

from OTXv2 import OTXv2
import argparse
import get_malicious
import hashlib


# Your API key
API_KEY = ''
OTX_SERVER = 'https://otx.alienvault.com/'
otx = OTXv2(API_KEY, server=OTX_SERVER)

parser = argparse.ArgumentParser(description='OTX CLI Example')
parser.add_argument('-ip', help='IP eg; 4.4.4.4', required=False)
parser.add_argument('-host',
                    help='Hostname eg; www.alienvault.com', required=False)
parser.add_argument(
    '-url', help='URL eg; http://www.alienvault.com', required=False)
parser.add_argument(
    '-hash', help='Hash of a file eg; 7b42b35832855ab4ff37ae9b8fa9e571', required=False)
parser.add_argument(
    '-file', help='Path to a file, eg; malware.exe', required=False)

args = vars(parser.parse_args())


if args['ip']:
    alerts = get_malicious.ip(otx, args['ip'])
    if len(alerts) > 0:
        print('Identified as potentially malicious')
        print(str(alerts))
    else:
        print('Unknown or not identified as malicious')

if args['host']:
    alerts = get_malicious.hostname(otx, args['host'])
    if len(alerts) > 0:
        print('Identified as potentially malicious')
        print(str(alerts))
    else:
        print('Unknown or not identified as malicious')

if args['url']:
    alerts = get_malicious.url(otx, args['url'])
    if len(alerts) > 0:
        print('Identified as potentially malicious')
        print(str(alerts))
    else:
        print('Unknown or not identified as malicious')

if args['hash']:
    alerts =  get_malicious.file(otx, args['hash'])
    if len(alerts) > 0:
        print('Identified as potentially malicious')
        print(str(alerts))
    else:
        print('Unknown or not identified as malicious')


if args['file']:
    hash = hashlib.md5(open(args['file'], 'rb').read()).hexdigest()
    alerts =  get_malicious.file(otx, hash)
    if len(alerts) > 0:
        print('Identified as potentially malicious')
        print(str(alerts))
    else:
        print('Unknown or not identified as malicious')

