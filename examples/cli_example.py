#!/usr/bin/env python

# Very Simple CLI example to get indicator details from Alienvault OTX

from OTXv2 import OTXv2
import IndicatorTypes
import argparse
import os

# store OTX API key in environment variable OTX_API_KEY
API_KEY = os.getenv("OTX_API_KEY")

otx = OTXv2(API_KEY)

parser = argparse.ArgumentParser(description='OTX CLI Example')
parser.add_argument('-i', '--ip', help='IP eg; 4.4.4.4', required=False)
parser.add_argument(
    '-d', '--domain', help='Domain eg; alienvault.com', required=False)
parser.add_argument('-ho', '--hostname',
                    help='Hostname eg; www.alienvault.com', required=False)
parser.add_argument(
    '-u', '--url', help='URL eg; http://www.alienvault.com', required=False)
parser.add_argument(
    '-m', '--md5', help='MD5 Hash of a file eg; 7b42b35832855ab4ff37ae9b8fa9e571', required=False)
parser.add_argument(
    '-p', '--pulse', help='Search pulses for a string eg; Dridex', required=False)
parser.add_argument('-s', '--subscribed', help='Get pulses you are subscribed to',
                    required=False, action='store_true')

args = vars(parser.parse_args())

if args["ip"]:
    print (str(otx.get_indicator_details_full(IndicatorTypes.IPv4, args["ip"])))

if args["domain"]:
    print (str(otx.get_indicator_details_full(IndicatorTypes.DOMAIN, args["domain"])))

if args["hostname"]:
    print (str(otx.get_indicator_details_full(IndicatorTypes.HOSTNAME, args["hostname"])))

if args["url"]:
    print (str(otx.get_indicator_details_full(IndicatorTypes.URL, args["url"])))

if args["md5"]:
    print (str(otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_MD5, args["md5"])))

if args["pulse"]:
    result = otx.search_pulses(args["pulse"])
    print (str(result.get('results')))

if args["subscribed"]:
    print (str(otx.getall(max_items=3, limit=5)))
