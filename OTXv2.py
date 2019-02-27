#!/usr/bin/env python

import json
import datetime
import requests
from requests.packages.urllib3.util import Retry
from requests.adapters import HTTPAdapter

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

import IndicatorTypes

# API URLs
API_V1_ROOT = "/api/v1"                                                   # API v1 base path
SUBSCRIBED = "{}/pulses/subscribed".format(API_V1_ROOT)                     # pulse subscriptions
EVENTS = "{}/pulses/events".format(API_V1_ROOT)                             # events (user actions)
SEARCH_PULSES = "{}/search/pulses".format(API_V1_ROOT)                      # search pulses
SEARCH_USERS = "{}/search/users".format(API_V1_ROOT)                        # search users
PULSE_DETAILS = "{}/pulses/".format(API_V1_ROOT)                            # pulse meta data
PULSE_INDICATORS = PULSE_DETAILS + "indicators"                             # pulse indicators
PULSE_CREATE = "{}/pulses/create".format(API_V1_ROOT)                       # create pulse
INDICATOR_DETAILS = "{}/indicators/".format(API_V1_ROOT)                    # indicator details
VALIDATE_INDICATOR = "{}/pulses/indicators/validate".format(API_V1_ROOT)    # indicator details


class InvalidAPIKey(Exception):
    def __init__(self, value=None):
        self.value = value or "Invalid API Key"

    def __str__(self):
        return repr(self.value)


class BadRequest(Exception):
    def __init__(self, value=None):
        self.value = value or "Bad Request"

    def __str__(self):
        return repr(self.value)


class RetryError(Exception):
    def __init__(self, value=None):
        self.value = value or "Exceeded maximum number of retries"

    def __str__(self):
        return repr(self.value)


class OTXv2(object):
    """
    Main class to interact with the AlienVault OTX API.
    """

    def __init__(self, api_key, proxy=None, server="https://otx.alienvault.com", project="SDK", user_agent=None):
        self.key = api_key
        self.server = server
        self.proxies = {'http': proxy} if proxy else {}
        self.request_session = None
        self.headers = {
            'X-OTX-API-KEY': self.key,
            'User-Agent': user_agent or 'OTX Python {}/1.1'.format(project),
            'Content-Type': 'application/json'
        }

    def session(self):
        if self.request_session is None:
            self.request_session = requests.Session()

            # This will allow 5 tries at a url, with an increasing backoff.  Only applies to a specific set of codes
            self.request_session.mount('https://', HTTPAdapter(
                max_retries=Retry(
                    total=5,
                    status_forcelist=[429, 500, 502, 503],
                    backoff_factor=5,
                )
            ))

        return self.request_session

    @classmethod
    def handle_response_errors(cls, response):
        def _response_json():
            try:
                return response.json()
            except Exception as e:
                return {'internal_error': 'Unable to decode response json: {}'.format(e)}

        if response.status_code == 403:
            raise InvalidAPIKey()
        elif response.status_code == 400:
            raise BadRequest(_response_json())
        elif str(response.status_code)[0] != "2":
            raise Exception("Unexpected http code: %r, response=%r", response.status_code, _response_json())

        return response

    def get(self, url, **kwargs):
        """
        Internal API for GET request on a OTX URL
        :param url: URL to retrieve
        :return: response in JSON object form
        """

        try:
            response = self.session().get(
                self.create_url(url, **kwargs),
                headers=self.headers,
                proxies=self.proxies,
            )
            return self.handle_response_errors(response).json()
        except requests.exceptions.RetryError:
            raise RetryError()

    def patch(self, url, body, **kwargs):
        """
        Internal API for POST request on a OTX URL
        :param url: URL to retrieve
        :param body: HTTP Body to send in request
        :return: response as dict
        """

        response = self.session().patch(
            self.create_url(url, **kwargs),
            data=json.dumps(body),
            headers=self.headers,
            proxies=self.proxies,
        )
        return self.handle_response_errors(response).json()

    def post(self, url, body, **kwargs):
        """
        Internal API for POST request on a OTX URL
        :param url: URL to retrieve
        :param body: HTTP Body to send in request
        :return: response as dict
        """

        response = self.session().post(
            self.create_url(url, **kwargs),
            data=json.dumps(body),
            headers=self.headers,
            proxies=self.proxies,
        )
        return self.handle_response_errors(response).json()

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
        uri = uri if uri.startswith("http") else self.server + uri
        if kwargs:
            uri += "?" + urlencode(kwargs)

        # print uri
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
        indicator_url += "{indicator_type}/{indicator}/{section}".format(
            indicator_type=indicator_type.slug,
            indicator=indicator,
            section=section
        )
        return indicator_url

    def walkapi_iter(self, url, max_page=None):
        next_page_url = url
        count = 0
        while next_page_url:
            count += 1
            if max_page and count > max_page:
                break

            data = self.get(next_page_url)
            for el in data['results']:
                yield el
            next_page_url = data["next"]

    def walkapi(self, url, iter=False, max_page=None):
        if iter:
            return self.walkapi_iter(url, max_page=max_page)
        else:
            return list(self.walkapi_iter(url, max_page=max_page))

    def getall(self, modified_since=None, author_name=None, limit=20, max_page=None, iter=False):
        """
        Get all pulses user is subscribed to.
        :param modified_since: datetime object representing earliest date you want returned in results
        :param author_name: Name of pulse author to limit results to
        :param limit: The page size to retrieve in a single request
        :return: the consolidated set of pulses for the user
        """
        args = {'limit': limit}
        if modified_since is not None:
            args['modified_since'] = modified_since
        if author_name is not None:
            args['author_name'] = author_name

        return self.walkapi(self.create_url(SUBSCRIBED, **args), iter=iter, max_page=max_page)

    def getall_iter(self, author_name=None, modified_since=None, limit=20, max_page=None):
        """
        Get all pulses user is subscribed to, yield results.
        :param modified_since: datetime object representing earliest date you want returned in results
        :param author_name: Name of pulse author to limit results to
        :param limit: The page size to retrieve in a single request
        :param max_page: if set, limits number of pages returned to 'max_page'
        :return: the consolidated set of pulses for the user
        """
        return self.getall(modified_since=modified_since, author_name=author_name, limit=limit, max_page=max_page, iter=True)

    def getsince(self, timestamp, limit=20, max_page=None):
        """
        Get all pulses modified since a particular time.
        :param timestamp: iso formatted date time string
        :param limit: Maximum number of results to return in a single request
        :return: the consolidated set of pulses for the user
        """

        return self.getall(limit=limit, modified_since=timestamp, max_page=max_page, iter=False)

    def getsince_iter(self, timestamp, limit=20, max_page=None):
        """
        Get all pulses modified since a particular time, yield results.
        :param timestamp: iso formatted date time string
        :param limit: Maximum number of results to return in a single request
        :return: the consolidated set of pulses for the user
        """
        return self.getall(limit=limit, modified_since=timestamp, max_page=max_page, iter=True)

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

    def get_all_indicators(self, indicator_types=IndicatorTypes.all_types, max_page=None):
        """
        Get all the indicators contained within your pulses of the IndicatorTypes passed.
        By default returns all IndicatorTypes.
        :param indicator_types: IndicatorTypes to return
        :return: yields the indicator object for use
        """
        name_list = IndicatorTypes.to_name_list(indicator_types)
        for pulse in self.getall_iter(max_page=max_page):
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
        return self.walkapi(self.create_url(EVENTS, limit=limit, since=timestamp))

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
        return self.walkapi(self.create_url(PULSE_DETAILS + str(pulse_id) + "/indicators", limit=limit))


    def edit_pulse(self, pulse_id, body):
        """
        Edits a pulse
        :param pulse_id: The pulse you are editing the indicators in
        :param body: The complete set of indicators this pulse will now contain
        eg; body: {
            "description": "New Description",
            "tags": {"add": ["addtag1", "addtag2"], "remove": ["remtag1"]}
        }
        :return: Return the new pulse
        """
        response = self.patch(self.create_url(PULSE_DETAILS + str(pulse_id)), body=body)
        return response


    def add_pulse_indicators(self, pulse_id, new_indicators):
        """
        Adds indicators to a pulse
        :param pulse_id: The pulse you are replacing the indicators with
        :param new_indicators: The set of new indicators
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

        body = {
            'indicators': {
                'add': indicators_to_add
            }
        }

        response = self.patch(self.create_url(PULSE_DETAILS + str(pulse_id)), body=body)
        return response

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
                indicators_to_amend.append({"id": indicator["id"], "expiration": yesterday.strftime("%Y-%m-%d"), "title": "Expired"})
            else:
                # Need this else statement, to cover indicators that appear, then go, then re-appear
                indicators_to_amend.append({"id": indicator["id"], "expiration": "", "title": "", "is_active": 1})
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
