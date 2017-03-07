#!/usr/bin/env python

import json
import datetime

import IndicatorTypes

# API URLs
API_V1_ROOT = "{}/api/v1"                                                   # API v1 base path
SUBSCRIBED = "{}/pulses/subscribed".format(API_V1_ROOT)                     # pulse subscriptions
EVENTS = "{}/pulses/events".format(API_V1_ROOT)                             # events (user actions)
SEARCH_PULSES = "{}/search/pulses".format(API_V1_ROOT)                      # search pulses
SEARCH_USERS = "{}/search/users".format(API_V1_ROOT)                        # search users
PULSE_DETAILS = "{}/pulses/".format(API_V1_ROOT)                            # pulse meta data
PULSE_INDICATORS = PULSE_DETAILS + "indicators"                             # pulse indicators
PULSE_CREATE = "{}/pulses/create".format(API_V1_ROOT)                       # create pulse
INDICATOR_DETAILS = "{}/indicators/".format(API_V1_ROOT)                    # indicator details
VALIDATE_INDICATOR = "{}/pulses/indicators/validate".format(API_V1_ROOT)    # indicator details


try:
    # For Python2
    from urllib2 import URLError, HTTPError, build_opener, ProxyHandler, urlopen, Request
except ImportError:
    # For Python3
    from urllib.error import URLError, HTTPError
    from urllib.request import build_opener, ProxyHandler, urlopen, Request


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
    """
    Main class to interact with the AlienVault OTX API.
    """

    def __init__(self, api_key, proxy=None, server="https://otx.alienvault.com", project="SDK"):
        self.key = api_key
        self.server = server
        self.proxy = proxy
        self.sdk = 'OTX Python {}/1.1'.format(project)

    def get(self, url):
        """
        Internal API for GET request on a OTX URL
        :param url: URL to retrieve
        :return: response in JSON object form
        """
        if self.proxy:
            proxy = ProxyHandler({'http': self.proxy})
            request = build_opener(proxy)
        else:
            request = build_opener()
        request.addheaders = [
            ('X-OTX-API-KEY', self.key),
            ('User-Agent', self.sdk)
        ]
        response = None
        try:
            response = request.open(url)
        except URLError as e:
            if isinstance(e, HTTPError):
                if e.code == 403:
                    raise InvalidAPIKey("Invalid API Key")
                elif e.code == 400:
                    raise BadRequest("Bad Request")
            else:
                raise e
        data = response.read().decode('utf-8')
        json_data = json.loads(data)
        return json_data



    def patch(self, url, body):
        """
        Internal API for POST request on a OTX URL
        :param url: URL to retrieve
        :param body: HTTP Body to send in request
        :return: response as dict
        """
        request = Request(url)
        request.add_header('X-OTX-API-KEY', self.key)
        request.add_header('User-Agent', self.sdk)
        request.add_header("Content-Type", "application/json")
        method = "PATCH"
        request.get_method = lambda: method
        if body:
            try:  # python2
                request.add_data(json.dumps(body))
            except AttributeError as ae:  # python3
                request.data = json.dumps(body).encode('utf-8')
        try:
            response = urlopen(request)
            data = response.read().decode('utf-8')
            json_data = json.loads(data)
            return json_data
        except URLError as e:
            if isinstance(e, HTTPError):
                if e.code == 403:
                    raise InvalidAPIKey("Invalid API Key")
                elif e.code == 400:
                    encoded_error = e.read()
                    decoded_error = encoded_error.decode('utf-8')
                    json.loads(decoded_error)
                    raise BadRequest(decoded_error)
        return {}

    def post(self, url, body):
        """
        Internal API for POST request on a OTX URL
        :param url: URL to retrieve
        :param body: HTTP Body to send in request
        :return: response as dict
        """
        request = Request(url)
        request.add_header('X-OTX-API-KEY', self.key)
        request.add_header('User-Agent', self.sdk)
        request.add_header("Content-Type", "application/json")
        method = "POST"
        request.get_method = lambda: method
        if body:
            try:  # python2
                request.add_data(json.dumps(body))
            except AttributeError as ae:  # python3
                request.data = json.dumps(body).encode('utf-8')
        try:
            response = urlopen(request)
            data = response.read().decode('utf-8')
            json_data = json.loads(data)
            return json_data
        except URLError as e:
            if isinstance(e, HTTPError):
                if e.code == 403:
                    raise InvalidAPIKey("Invalid API Key")
                elif e.code == 400:
                    encoded_error = e.read()
                    decoded_error = encoded_error.decode('utf-8')
                    json.loads(decoded_error)
                    raise BadRequest(decoded_error)
        return {}

    def create_pulse(self, **kwargs):
        """
        Create a pulse via HTTP Post (Content Type: application/json).
        Notes:
            If `TLP` is one of: ['red', 'amber'], `public` must be false.
            `name` field is required
            Default values (unless specified):
                - public: True
                - TLP: 'green'

        :param kwargs containing pulse to submit
            :param name(string, required) pulse name
            :param public(boolean, required) long form description of threat
            :param description(string) long form description of threat
            :param tlp(string) Traffic Light Protocol level for threat sharing
            :param tags(list of strings) short keywords to associate with your pulse
            :param references(list of strings, preferably URLs) external references for this threat
            :param indicators(list of objects) IOCs to include in pulse
        :return: request body response
        :raises BadRequest (400) On failure, BadRequest will be raised containing the invalid fields.

        Examples:
        Python kwargs can be used in two ways.  You can call create_pulse passing a dict, or named arguments.
        With a dict:
            otx = OTXv2("mysecretkey")  # replace with your api key
            body = {'name': pulse_name, 'public': False, 'indicators': indicator_list, 'TLP': 'green', ...}
            otx.create_pulse(**body)  # the dict will be expanded into the args.
        Or with named args:
            otx = OTXv2("mysecretkey")  # replace with your api key
            otx.create_pulse(name=pulse_name, public=False, indicators=indicator_list, TLP='green')
        """
        body = {
            'name': kwargs.get('name', ''),
            'description': kwargs.get('description', ''),
            'public': kwargs.get('public', True),
            'TLP': kwargs.get('TLP', kwargs.get('tlp', 'green')),
            'tags': kwargs.get('tags', []),
            'references': kwargs.get('references', []),
            'indicators': kwargs.get('indicators', [])
        }
        # name is required.  Public is too but will be set True if not specified.
        if not body.get('name'):
            raise ValueError('Name required.  Please resubmit your pulse with a name (string, 5-64 chars).')
        return self.post(self.create_url(PULSE_CREATE), body=body)

    def validate_indicator(self, indicator_type, indicator, description=""):
        """
        The goal of validate_indicator is to aid you in pulse creation.  Use this method on each indicator before
        calling create_pulse to ensure success in the create call.  If you supply invalid indicators in a create call,
        the pulse will not be created.

        :param indicator: indicator value (string)
        :param indicator_type: an IndicatorTypes object (i.e. IndicatorTypes.DOMAIN)
        :param description: a short descriptive string can be sent to the validator for length checking
        :return:
        """
        if not indicator:
            raise ValueError("please supply `indicator` when calling validate_indicator")
        if not indicator_type:
            raise ValueError("please supply `indicator` when calling validate_indicator")
        # if caller supplied object instance, use name field
        if isinstance(indicator_type, IndicatorTypes.IndicatorTypes):
            indicator_type = indicator_type.name
        elif indicator_type not in IndicatorTypes.to_name_list(IndicatorTypes.all_types):
            raise ValueError("Indicator type: {} is not a valid type.".format(indicator_type))
        # indicator type is valid, let's valdate against the otx api
        body = {
            'indicator': indicator,
            'type': indicator_type,
            'description': description
        }
        response = self.post(self.create_url(VALIDATE_INDICATOR), body=body)
        return response

    def create_url(self, url_path, **kwargs):
        """ Turn a path into a valid fully formatted URL. Supports query parameter formatting as well.

        :param url_path: Request path (i.e. "/search/pulses")
        :param kwargs: key value pairs to be added as query parameters (i.e. limit=10, page=5)
        :return: a formatted url (i.e. "/search/pulses")
        """
        uri = url_path.format(self.server)
        if kwargs.items():
            uri += "?"
            for parameter, value in kwargs.items():
                uri += parameter
                uri += "="
                uri += str(value)
                uri += "&"
        return uri

    def create_indicator_detail_url(self, indicator_type, indicator, section='general'):
        """ Build a valid indicator detail url.  This api contains all data we have about indicators.

        Only indicators with IndicatorTypes.api_support = True should be used.

        :param indicator_type: IndicatorType instance
        :param indicator: String indicator (i.e. "69.73.130.198", "mail.vspcord.com")
        :param section: Section from IndicatorTypes.section.  Default is general info
        :return: formatted URL string
        """
        indicator_url = self.create_url(INDICATOR_DETAILS)
        indicator_url = indicator_url + "{indicator_type}/{indicator}/{section}".format(indicator_type=indicator_type.slug,
                                                                                        indicator=indicator,
                                                                                        section=section)
        return indicator_url

    def getall(self, limit=20):
        """
        Get all pulses user is subscribed to.
        :param limit: The page size to retrieve in a single request
        :return: the consolidated set of pulses for the user
        """
        pulses = []
        next_page_url = self.create_url(SUBSCRIBED, limit=limit)
        while next_page_url:
            json_data = self.get(next_page_url)
            for r in json_data["results"]:
                pulses.append(r)
            next_page_url = json_data["next"]
        return pulses

    def getall_iter(self, limit=20):
        """
        Get all pulses user is subscribed to, yield results.
        :param limit: The page size to retrieve in a single request
        :return: the consolidated set of pulses for the user
        """
        next_page_url = self.create_url(SUBSCRIBED, limit=limit)
        while next_page_url:
            json_data = self.get(next_page_url)
            for r in json_data["results"]:
                yield r
            next_page_url = json_data["next"]

    def getsince(self, timestamp, limit=20):
        """
        Get all pulses modified since a particular time.
        :param timestamp: iso formatted date time string
        :param limit: Maximum number of results to return in a single request
        :return: the consolidated set of pulses for the user
        """
        pulses = []
        next_page_url = self.create_url(SUBSCRIBED, limit=limit, modified_since=timestamp)
        while next_page_url:
            json_data = self.get(next_page_url)
            for r in json_data["results"]:
                pulses.append(r)
            next_page_url = json_data["next"]
        return pulses

    def getsince_iter(self, timestamp, limit=20):
        """
        Get all pulses modified since a particular time, yield results.
        :param timestamp: iso formatted date time string
        :param limit: Maximum number of results to return in a single request
        :return: the consolidated set of pulses for the user
        """
        next_page_url = self.create_url(SUBSCRIBED, limit=limit, modified_since=timestamp)
        while next_page_url:
            json_data = self.get(next_page_url)
            for r in json_data["results"]:
                yield r
            next_page_url = json_data["next"]

    def search_pulses(self, query, max_results=25):
        """
        Get all pulses with text matching `query`.
        :param query: The text to search for
        :param max_results: Limit the number of pulses returned in response
        :return: All pulses matching `query`
        """
        search_pulses_url = self.create_url(SEARCH_PULSES, q=query, page=1, limit=20)
        return self._get_paginated_resource(search_pulses_url, max_results=max_results)

    def search_users(self, query, max_results=25):
        """
        Get all pulses with text matching `query`.
        :param query: The text to search for
        :param max_results: Limit the number of users returned in response
        :return: List of users with username matching `query`
        """
        search_users_url = self.create_url(SEARCH_USERS, q=query, limit=20, page=1)
        return self._get_paginated_resource(search_users_url, max_results=max_results)

    def _get_paginated_resource(self, url=SUBSCRIBED, max_results=25):
        """
        Get all pages of a particular API resource, and retain additional fields.

        :param url: URL for first page of a paginated list api. Default is list subscribed pulses.
        :param max_results: Limit the number of objects returned.
        :return: results and additional fields as dict
        """
        results = []
        next_page_url = url
        additional_fields = {}
        while next_page_url and len(results) < max_results:
            json_data = self.get(next_page_url)
            max_results -= len(json_data.get('results'))
            for r in json_data.pop("results"):
                results.append(r)
            next_page_url = json_data.pop("next")
            json_data.pop('previous', '')
            if json_data.items():
                additional_fields.update(json_data)
        resource = {"results": results[:max_results]}
        resource.update(additional_fields)
        return resource

    def get_all_indicators(self, indicator_types=IndicatorTypes.all_types):
        """
        Get all the indicators contained within your pulses of the IndicatorTypes passed.
        By default returns all IndicatorTypes.
        :param indicator_types: IndicatorTypes to return
        :return: yields the indicator object for use
        """
        name_list = IndicatorTypes.to_name_list(indicator_types)
        for pulse in self.getall_iter():
            for indicator in pulse["indicators"]:
                if indicator["type"] in name_list:
                    yield indicator

    def getevents_since(self, timestamp, limit=20):
        """
        Get all events (activity) created or updated since a timestamp
        :param timestamp: ISO formatted datetime string to restrict results (not older than timestamp).
        :param limit: The page size to retrieve in a single request
        :return: the consolidated set of pulses for the user
        """
        events = []
        next_page_url = self.create_url(EVENTS, limit=limit, since=timestamp)
        while next_page_url:
            json_data = self.get(next_page_url)
            for r in json_data["results"]:
                events.append(r)
            next_page_url = json_data["next"]
        return events

    def get_pulse_details(self, pulse_id):
        """
        For a given pulse_id, get the details of an arbitrary pulse.0
        :param pulse_id: object id for pulse
        :return: Pulse as dict
        """
        pulse_url = self.create_url(PULSE_DETAILS + str(pulse_id))
        meta_data = self.get(pulse_url)
        return meta_data

    def get_pulse_indicators(self, pulse_id, limit=20):
        """
        For a given pulse_id, get list of indicators (IOCs)
        :param pulse_id: Object ID specify which pulse to get indicators from
        :return: Indicator list
        """
        indicators = []
        next_page_url = self.create_url(PULSE_DETAILS + str(pulse_id) + "/indicators", limit=limit)
        while next_page_url:
            json_data = self.get(next_page_url)
            for r in json_data["results"]:
                indicators.append(r)
            next_page_url = json_data["next"]
        return indicators

    def replace_pulse_indicators(self, pulse_id, new_indicators):
        """
        Replaces indicators in a pulse - new indicators are added, those that are no longer present are set to expire
        :param pulse_id: The pulse you are replacing the indicators with
        :param new_indicators: The complete set of indicators this pulse will now contain
        :return: Return the new pulse

        """
        current_indicators = self.get_pulse_indicators(pulse_id)
        current_indicator_values = []
        current_indicator_indicators = []

        for indicator in current_indicators:
            current_indicator_values.append(indicator["indicator"])
            current_indicator_indicators.append(indicator)

        new_indicator_values = []
        indicators_to_add = []

        for indicator in new_indicators:
            new_indicator_value = indicator["indicator"]
            new_indicator_values.append(new_indicator_value)
            if new_indicator_value not in current_indicator_values:
                indicators_to_add.append(indicator)

        indicators_to_amend = []
        for indicator in current_indicator_indicators:
            if indicator["indicator"] not in new_indicator_values:
                yesterday = datetime.datetime.now() - datetime.timedelta(days=1)
                indicators_to_amend.append({"id" : indicator["id"], "expiration": yesterday.strftime("%Y-%m-%d"), "title" : "Expired"})
            else:
                # Need this else statement, to cover indicators that appear, then go, then re-appear
                indicators_to_amend.append({"id" : indicator["id"], "expiration": "", "title" : "", "is_active": 1})
        body = {
            'indicators': {
                'add': indicators_to_add,
                'edit': indicators_to_amend
            }
        }

        response = self.patch(self.create_url(PULSE_DETAILS + str(pulse_id)), body=body)
        return response



    def get_indicator_details_by_section(self, indicator_type, indicator, section='general'):
        """
        The Indicator details endpoints are split into sections.  Obtain a specific section for an indicator.
        :param indicator_type: IndicatorType instance
        :param indicator: String indicator (i.e. "69.73.130.198", "mail.vspcord.com")
        :param section: Section from IndicatorTypes.section.  Default is general info
        :return: Return indicator details as dict

        """
        if not indicator_type.api_support:
            raise TypeError("IndicatorType {0} is not currently supported.".format(indicator_type))
        if section not in indicator_type.sections:
            raise TypeError("Section {0} is not currently supported for indicator type: {0}")
        indicator_url = self.create_indicator_detail_url(indicator_type, indicator, section)
        indicator_details = self.get(indicator_url)
        return indicator_details

    def get_indicator_details_full(self, indicator_type, indicator):
        """
        Obtain all sections for an indicator.
        :param indicator_type: IndicatorType instance
        :param indicator: String indicator (i.e. "69.73.130.198", "mail.vspcord.com")
        :return: dict with sections as keys and results for each call as values.
        """
        indicator_dict = {}
        for section in indicator_type.sections:
            indicator_url = self.create_indicator_detail_url(indicator_type, indicator, section)
            indicator_dict[section] = self.get(indicator_url)
        return indicator_dict
