#!/usr/bin/env python

import httplib
import urlparse
import urllib
import urllib2
import simplejson as json
import time
import re
import logging
import datetime

logger = logging.getLogger("OTXv2")

class InvalidAPIKey(Exception):
	def __init__(self, value):
		self.value = value

	def __str__(self):
		return repr(self.value)

class BadRequest(Exception):
	def __init__(self, value):
		self.value = value

	def __str__(self):
		return repr(self.value)

class OTXv2(object):
	def __init__(self, key, server="http://otx.alienvault.com"):
		self.key = key
		self.server = server 

	def get(self, url):
		request = urllib2.build_opener()
		request.addheaders = [('X-OTX-API-KEY', self.key)]
		response = None
		try:
			response = request.open(url)
		except urllib2.URLError, e:
			if e.code == 403:
				raise InvalidAPIKey("Invalid API Key")
			elif e.code == 400:
				raise BadRequest("Bad Request")
		data = response.read()
		json_data = json.loads(data)
		return json_data

	def getall(self):
		pulses = []
		next = "%s/api/v1/pulses/subscribed?limit=20" % self.server
		while next:
			json_data = self.get(next)
			for r in json_data["results"]:
				pulses.append(r)
			next = json_data["next"]
		return pulses

	def getsince(self, mytimestamp):
		pulses = []
		next = "%s/api/v1/pulses/subscribed?limit=20&modified_since=%s" % (self.server, mytimestamp)
		while next:
			json_data = self.get(next)
			for r in json_data["results"]:
				pulses.append(r)
			next = json_data["next"]
		return pulses





