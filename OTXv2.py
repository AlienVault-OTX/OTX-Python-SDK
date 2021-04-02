#!/usr/bin/env python

import copy
import datetime
import dateutil.parser
import json
import logging
import os
import pytz
import re
import requests
from requests.packages.urllib3.util import Retry
from requests.adapters import HTTPAdapter
from six import string_types

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

import IndicatorTypes

# API URLs
API_V1_ROOT = "/api/v1"                                                       # API v1 base path
SUBSCRIBED = "{}/pulses/subscribed".format(API_V1_ROOT)                       # pulse subscriptions
EVENTS = "{}/pulses/events".format(API_V1_ROOT)                               # events (user actions)
SEARCH_PULSES = "{}/search/pulses".format(API_V1_ROOT)                        # search pulses
SEARCH_USERS = "{}/search/users".format(API_V1_ROOT)                          # search users
PULSE_DETAILS = "{}/pulses/".format(API_V1_ROOT)                              # pulse meta data
PULSE_INDICATORS = PULSE_DETAILS + "indicators"                               # pulse indicators
PULSE_CREATE = "{}/pulses/create".format(API_V1_ROOT)                         # create pulse
PULSE_ADD_GROUP = "{}/groups/{{}}/add_pulse?pulse_id={{}}".format(API_V1_ROOT)
PULSE_REMOVE_GROUP = "{}/groups/{{}}/remove_pulse?pulse_id={{}}".format(API_V1_ROOT)
USER_PULSES = "{}/pulses/user/{{}}".format(API_V1_ROOT)                       # pulse feed for a user
MY_PULSES = "{}/pulses/my".format(API_V1_ROOT)                       # pulse feed for a user
SUBSCRIBE_PULSE = "{}/pulses/{{}}/subscribe".format(API_V1_ROOT)              # subscribe to pulse
CLONE_PULSE = "{}/pulses/{{}}/clone".format(API_V1_ROOT)            # clone pulse
UNSUBSCRIBE_PULSE = "{}/pulses/{{}}/unsubscribe".format(API_V1_ROOT)          # unsubscribe from pulse
INDICATOR_DETAILS = "{}/indicators/".format(API_V1_ROOT)                      # indicator details
VALIDATE_INDICATOR = "{}/pulses/indicators/validate".format(API_V1_ROOT)      # indicator details
SUBSCRIBE_USER = "{}/users/{{}}/subscribe/".format(API_V1_ROOT)               # subscribe to user
UNSUBSCRIBE_USER = "{}/users/{{}}/unsubscribe/".format(API_V1_ROOT)           # unsubscribe from user
FOLLOW_USER = "{}/users/{{}}/follow".format(API_V1_ROOT)                      # follow user
USER_INFO = "{}/users/{{}}".format(API_V1_ROOT)                               # follow user
UNFOLLOW_USER = "{}/users/{{}}/unfollow".format(API_V1_ROOT)                  # unfollow user
SUBMIT_FILE = "{}/indicators/submit_file".format(API_V1_ROOT)                 # submit malware sample for analysis
SUBMITTED_FILES = "{}/indicators/submitted_files".format(API_V1_ROOT)         # status of submitted samples
SUBMIT_URL = "{}/indicators/submit_url".format(API_V1_ROOT)                   # submit url for analysis
SUBMIT_URLS = "{}/indicators/submit_urls".format(API_V1_ROOT)                 # submit multiple urls for analysis
SUBMITTED_URLS = "{}/indicators/submitted_urls".format(API_V1_ROOT)           # status of submitted urls
DELETE_PULSE = "{}/pulses/{{}}/delete".format(API_V1_ROOT)                   # Delete a pulse



# logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()


class InvalidAPIKey(Exception):
    def __init__(self, value=None):
        self.value = value or "Invalid API Key"

    def __str__(self):
        return repr(self.value)


class NotFound(Exception):
    def __init__(self, value=None):
        self.value = value or "Not Found"

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

    def __init__(
        self, api_key, proxy=None, proxy_https=None, server="https://otx.alienvault.com", project="SDK",
        user_agent=None, verify=True, cert=None
    ):
        self.key = api_key
        self.server = server
        self.verify = verify
        self.cert = cert

        self.proxies = {}
        if proxy:
            self.proxies['http'] = proxy
        if proxy_https:
            self.proxies['https'] = proxy_https

        self.request_session = None
        self.headers = {
            'X-OTX-API-KEY': self.key,
            'User-Agent': user_agent or 'OTX Python {}/1.5.12'.format(project),
            'Content-Type': 'application/json'
        }

    def session(self):
        if self.request_session is None:
            self.request_session = requests.Session()

            # This will allow 5 tries at a url, with an increasing backoff.  Only applies to a specific set of codes
            self.request_session.mount('https://', HTTPAdapter(
                max_retries=Retry(
                    total=5,
                    status_forcelist=[429, 500, 502, 503, 504],
                    backoff_factor=1,
                )
            ))

        return self.request_session

    def now(self):
        return pytz.utc.localize(datetime.datetime.utcnow())

    @classmethod
    def fix_date(cls, date_str):
        if date_str is None:
            return None

        if isinstance(date_str, datetime.datetime):
            dt = date_str
        else:
            dt = dateutil.parser.parse(date_str) if date_str else None

        if dt and dt.tzinfo is None:
            dt = pytz.utc.localize(dt)

        return dt

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
        elif response.status_code == 404:
            raise NotFound()
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
                verify=self.verify,
                cert=self.cert,
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
            verify=self.verify,
            cert=self.cert,
        )
        return self.handle_response_errors(response).json()

    def post(self, url, body=None, headers=None, files=None, **kwargs):
        """
        Internal API for POST request on a OTX URL
        :param url: URL to retrieve
        :param body: HTTP Body to send in request
        :param headers: (optional) dict of headers to use, instead of default headers
        :param files: (optional) list of file tuples, if posting multipart form data
        :return: response as dict
        """

        response = self.session().post(
            self.create_url(url, **kwargs),
            data=json.dumps(body) if body else None,
            files=files,
            headers=headers or self.headers,
            proxies=self.proxies,
            verify=self.verify,
            cert=self.cert,
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
            :param group_ids(list of integers) Group IDs for groups pulse should be added to.  You must be a member of the group and able to add pulses to the group
            :param adversary(string) Name of adversary related to pulse
            :param targeted_countries(list of strings, or list of ints) List of affected or related countries.  Can use official country name, or better yet the 3-character ISO 3166 country codes
            :param industries(list of strings) list of industries related to pulse
            :param malware_families(list of strings) list of malware families related to pulse
            :param attack_ids(list of strings) list of ATT&CK ids related to pulse

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
            'indicators': kwargs.get('indicators', []),
            'group_ids': kwargs.get('group_ids', []),
            'adversary': kwargs.get('adversary'),
            'targeted_countries': kwargs.get('targeted_countries', []),
            'industries': kwargs.get('industries', []),
            'malware_families': kwargs.get('malware_families', []),
            'attack_ids': kwargs.get('attack_ids', [])
        }

        # name is required.  Public is too but will be set True if not specified.
        if not body.get('name'):
            raise ValueError('Name required.  Please resubmit your pulse with a name (string, 5-64 chars).')
        return self.post(self.create_url(PULSE_CREATE), body=body)

    def group_add_pulse(self, group_id, pulse_id):
        url = PULSE_ADD_GROUP.format(group_id, pulse_id)
        return self.get(url)

    def group_remove_pulse(self, group_id, pulse_id):
        url = PULSE_REMOVE_GROUP.format(group_id, pulse_id)
        return self.get(url)

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
        uri = uri if uri.startswith("http") else self.server.rstrip('/') + uri
        if kwargs:
            uri += "?" + urlencode(kwargs)

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

    def walkapi_iter(self, url, max_page=None, max_items=None, method='GET', body=None):
        next_page_url = url
        count = 0
        item_count = 0
        while next_page_url:
            count += 1
            if max_page and count > max_page:
                break

            if method == 'GET':
                data = self.get(next_page_url)
            elif method == 'POST':
                data = self.post(next_page_url, body=body)
            else:
                raise Exception("Unsupported method type: {}".format(method))

            for el in data['results']:
                item_count += 1
                if max_items and item_count > max_items:
                    break

                yield el

            next_page_url = data["next"]

    def walkapi(self, url, iter=False, max_page=None, max_items=None, method='GET', body=None):
        if iter:
            return self.walkapi_iter(url, max_page=max_page, max_items=max_items, method=method, body=body)
        else:
            return list(self.walkapi_iter(url, max_page=max_page, max_items=max_items, method=method, body=body))

    def getall(self, modified_since=None, author_name=None, limit=50, max_page=None, max_items=None, iter=False):
        """
        Get all pulses user is subscribed to.
        :param modified_since: datetime object representing earliest date you want returned in results
        :param author_name: Name of pulse author to limit results to
        :param limit: The page size to retrieve in a single request
        :return: the consolidated set of pulses for the user
        """
        args = {'limit': limit}
        if modified_since is not None:
            if isinstance(modified_since, (datetime.datetime, datetime.date)):
                modified_since = modified_since.isoformat()

            args['modified_since'] = modified_since
        if author_name is not None:
            args['author_name'] = author_name

        return self.walkapi(
            self.create_url(SUBSCRIBED, **args), iter=iter,
            max_page=max_page, max_items=max_items
        )

    def getall_iter(self, author_name=None, modified_since=None, limit=50, max_page=None, max_items=None):
        """
        Get all pulses user is subscribed to, yield results.
        :param modified_since: datetime object representing earliest date you want returned in results
        :param author_name: Name of pulse author to limit results to
        :param limit: The page size to retrieve in a single request
        :param max_page: if set, limits number of pages returned to 'max_page'
        :return: the consolidated set of pulses for the user
        """
        return self.getall(
            modified_since=modified_since, author_name=author_name, limit=limit,
            max_page=max_page, max_items=max_items, iter=True,
        )

    def getsince(self, timestamp, limit=50, max_page=None, max_items=None):
        """
        Get all pulses modified since a particular time.
        :param timestamp: iso formatted date time string
        :param limit: Maximum number of results to return in a single request
        :return: the consolidated set of pulses for the user
        """

        return self.getall(limit=limit, modified_since=timestamp, max_page=max_page, max_items=max_items, iter=False)

    def getsince_iter(self, timestamp, limit=50, max_page=None, max_items=None):
        """
        Get all pulses modified since a particular time, yield results.
        :param timestamp: iso formatted date time string
        :param limit: Maximum number of results to return in a single request
        :return: the consolidated set of pulses for the user
        """
        return self.getall(limit=limit, modified_since=timestamp, max_page=max_page, max_items=max_items, iter=True)

    def search_pulses(self, query, max_results=25):
        """
        Get all pulses with text matching `query`.
        :param query: The text to search for
        :param max_results: Limit the number of pulses returned in response
        :return: All pulses matching `query`
        """
        search_pulses_url = self.create_url(SEARCH_PULSES, q=query, page=1, limit=25)
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
            for r in json_data.pop("results"):
                results.append(r)
            next_page_url = json_data.pop("next")
            json_data.pop('previous', '')
            if json_data.items():
                additional_fields.update(json_data)
        resource = {"results": results[:max_results]}
        resource.update(additional_fields)
        return resource

    def get_all_indicators(self, author_name=None, modified_since=None, indicator_types=IndicatorTypes.all_types, limit=50, max_page=None, max_items=None):
        """
        Get all the indicators contained within your pulses of the IndicatorTypes passed.
        By default returns all IndicatorTypes.
        :param indicator_types: IndicatorTypes to return
        :param author_name limit indicators to ones found in pulses authored by author_name
        :param modified_since limit indicators to ones found in pulses modified since modified_since
        :return: yields the indicator object for use
        """
        name_list = IndicatorTypes.to_name_list(indicator_types)
        for pulse in self.getall_iter(author_name=author_name, modified_since=modified_since, limit=limit, max_page=max_page, max_items=max_items):
            for indicator in pulse["indicators"]:
                if indicator["type"] in name_list:
                    yield indicator

    def getevents_since(self, timestamp, limit=50, max_page=None, max_items=None, iter=False):
        """
        Get all events (activity) created or updated since a timestamp
        :param timestamp: ISO formatted datetime string to restrict results (not older than timestamp).
        :param limit: The page size to retrieve in a single request
        :return: the consolidated set of pulses for the user
        """
        if isinstance(timestamp, (datetime.datetime, datetime.date)):
            timestamp = timestamp.isoformat()

        return self.walkapi(
            self.create_url(EVENTS, limit=limit, since=timestamp, iter=iter),
            max_page=max_page, max_items=max_items,
        )

    def get_pulse_details(self, pulse_id):
        """
        For a given pulse_id, get the details of an arbitrary pulse.0
        :param pulse_id: object id for pulse
        :return: Pulse as dict
        """

        if not isinstance(pulse_id, string_types) or not re.match(r"^[0-9a-zA-Z]{24}$", pulse_id):
           raise BadRequest("pulse_id should be a 24 character hex string")

        pulse_url = self.create_url(PULSE_DETAILS + str(pulse_id))
        meta_data = self.get(pulse_url)
        return meta_data

    def delete_pulse(self, pulse_id):
        """
        For a given pulse_id, delete it
        :param pulse_:od object id for pulse

        """
        if not isinstance(pulse_id, string_types) or not re.match(r"^[0-9a-zA-Z]{24}$", pulse_id):
            raise BadRequest("pulse_id should be a 24 character hex string")
        pulse_url = self.create_url(DELETE_PULSE.format(pulse_id))
        return self.get(pulse_url)

    def get_pulse_indicators(self, pulse_id, include_inactive=False, limit=1000):
        """
        For a given pulse_id, get list of indicators (IOCs)
        :param pulse_id: Object ID specify which pulse to get indicators from
        :return: Indicator list
        """

        if not isinstance(pulse_id, string_types) or not re.match(r"^[0-9a-zA-Z]{24}$", pulse_id):
           raise BadRequest("pulse_id should be a 24 character hex string")

        url = self.create_url(PULSE_DETAILS + str(pulse_id) + "/indicators", limit=limit, include_inactive=1 if include_inactive else 0)
        return self.walkapi(url)

    def edit_pulse(self, pulse_id, body):
        """
        Edits a pulse
        :param pulse_id: The pulse you are editing the indicators in
        :param body: The set of diffs you wish to make to the pulse indicators
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
        :return: The updated pulse
        """

        response = self.edit_pulse(pulse_id, body={
            'indicators': {
                'add': new_indicators
            }
        })
        return response

    def add_or_update_pulse_indicators(self, pulse_id, indicators):
        """
        Add indicators to pulse if not currently present, otherwise add indicators to pulse as new
        :param pulse_id: The pulse id you're updating
        :param indicators: the indicators you are adding or updating
        :return: The updated pulse
        """

        current_indicators = {x['indicator']: x for x in self.get_pulse_indicators(pulse_id, include_inactive=True, limit=2000)}

        indicators_to_add = []
        indicators_to_update = []

        for indicator in indicators:
            indicator = copy.deepcopy(indicator)
            if indicator['indicator'] in current_indicators:
                indicator = copy.deepcopy(indicator)
                indicator['id'] = current_indicators[indicator['indicator']]['id']
                if 'expiration' in indicator and 'is_active' not in indicator:
                    if self.fix_date(indicator['expiration']) > self.now():
                        indicator['is_active'] = 1
                indicators_to_update.append(indicator)
            else:
                indicators_to_add.append(indicator)

        body = {
            'indicators': {
                'add': indicators_to_add,
                'edit': indicators_to_update,
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

        expire_date = datetime.datetime.utcnow().isoformat()
        current_indicators = {x['indicator']: x for x in self.get_pulse_indicators(pulse_id, include_inactive=True, limit=2000)}

        indicators_to_add = []
        indicators_to_amend = []

        for indicator in new_indicators:
            if indicator['indicator'] not in current_indicators:
                indicators_to_add.append(indicator)
            else:
                indicator.update({
                    'id': current_indicators[indicator['indicator']]['id'],
                    'title': indicator.get('title', ''),
                    'expiration': indicator.get('expiration', ''),
                    'is_active': 1,
                })
                indicators_to_amend.append(indicator)
                del current_indicators[indicator['indicator']]

        for indicator in current_indicators.values():
            indicators_to_amend.append({"id": indicator["id"], "expiration": expire_date, "title": "Expired"})

        body = {'indicators': {'add': indicators_to_add, 'edit': indicators_to_amend}}

        response = self.patch(self.create_url(PULSE_DETAILS + str(pulse_id)), body=body)
        return response

    def remove_pulse_indicators(self, pulse_id, indicator_ids):
        body = {'indicators': {'remove': [{'id': i} for i in indicator_ids]}}
        return self.patch(self.create_url(PULSE_DETAILS + str(pulse_id)), body=body)

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

    def subscribe_to_user(self, username):
        url = SUBSCRIBE_USER.format(username)
        return self.get(url)

    def unsubscribe_from_user(self, username):
        url = UNSUBSCRIBE_USER.format(username)
        return self.get(url)

    def get_user(self, username, detailed=True):
        url = USER_INFO.format(username)
        if detailed:
            url += '?detailed=1'

        return self.get(url)

    def get_user_pulses(self, username, query=None, max_items=200):
        return self.walkapi(self.create_url(USER_PULSES.format(username), limit=50, q=query), max_items=max_items)

    def get_my_pulses(self, query=None, max_items=200):
        return self.walkapi(self.create_url(MY_PULSES, limit=50, q=query), max_items=max_items)

    def follow_user(self, username):
        url = FOLLOW_USER.format(username)
        return self.get(url)

    def unfollow_user(self, username):
        url = UNFOLLOW_USER.format(username)
        return self.get(url)

    def subscribe_to_pulse(self, pulse_id):
        url = SUBSCRIBE_PULSE.format(pulse_id)
        return self.get(url)

    def unsubscribe_from_pulse(self, pulse_id):
        url = UNSUBSCRIBE_PULSE.format(pulse_id)
        return self.get(url)

    def clone_pulse(self, pulse_id, new_name=None):
        new_name = new_name or p['name']
        url = CLONE_PULSE.format(pulse_id)
        return self.post(url, body={'name': new_name})

    def submit_file(self, filename=None, file_handle=None):
        """
        Submit malware sample for analysis.  If you pass 'file_handle' then data will be read
        from it as if it were an open file handle.  If you don't, then the file identified by 'filename'
        will be opened and read from

        :param filename: path to file to be uploaded
        :param file_handle: file-like object that can be read from
        :return: dict with status of submission
        """
        headers = copy.deepcopy(self.headers)
        headers.pop('Content-Type', None)

        do_close = file_handle is None
        if file_handle is None:
            file_handle = open(filename, "rb")

        try:
            return self.post(
                self.create_url(SUBMIT_FILE),
                files={
                    'file': (
                        filename or 'unknown',
                        file_handle,
                        'application/octet-stream'
                    )
                },
                headers=headers
            )
        finally:
            if do_close:
                file_handle.close()

    def submitted_files(self, limit=100, hashes=None, first_page=1, max_page=None, max_items=None):
        """
        Get status of submitted files
        :param hashes: list of sha256 hashes to check the results of (optional)
        :return: list of dicts, each dict describing the status of one file
        """
        return self.walkapi(
            self.create_url(SUBMITTED_FILES),
            max_page=max_page,
            method='POST',
            body={
                'hashes': hashes,
                'page': first_page,
                'limit': limit,
            },
        )

    def submit_url(self, url):
        """
        Submit a single url for analysis.  If you have more than one url to submit, use submit_urls
        :param url: url to be analyzed
        :return: dict with status of submission
        """
        return self.post(
            self.create_url(SUBMIT_URL),
            {'url': url}
        )

    def submit_urls(self, urls):
        """
        Submit multiple urls for analysis
        :param url: list of urls to be analyzed
        :return: dict with status of submission
        """
        return self.post(
            self.create_url(SUBMIT_URLS),
            {'urls': urls}
        )

    def submitted_urls(self, limit=1000, first_page=1, max_page=None, max_items=None):
        return self.walkapi(
            self.create_url(SUBMITTED_URLS, page=first_page, limit=limit),
            max_page=max_page, max_items=max_items
        )


class OTXv2Cached(OTXv2):
    DATA_FIELDS = {
        'last_subscription_fetch': 'datetime',
        'last_events_fetch': 'datetime',
    }

    def __init__(self, api_key, cache_dir=None, max_age=None, *args, **kwargs):
        super(OTXv2Cached, self).__init__(api_key=api_key, *args, **kwargs)

        self.cache_dir = cache_dir or os.path.expanduser("~/.otxv2_cache")
        self.max_age = max_age
        self.last_subscription_fetch = None
        self.last_events_fetch = None

        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)

        logger.info("Using cache_dir=%s, max_age=%s", self.cache_dir, self.max_age)

        self.load_data()

    def load_data(self):
        datfile = os.path.join(self.cache_dir, 'data.json')

        if os.path.exists(datfile):
            with open(datfile) as f:
                data = json.load(f)
                for k, v in self.DATA_FIELDS.items():
                    val = data[k]
                    if v == 'datetime':
                        val = dateutil.parser.parse(val) if val else None

                    setattr(self, k, val)

    def save_data(self):
        datfile = os.path.join(self.cache_dir, 'data.json')

        data = {}
        for k, v in self.DATA_FIELDS.items():
            val = getattr(self, k)
            if v == 'datetime':
                val = val.isoformat() if val else None
            data[k] = val

        with open(datfile, 'w') as f:
            json.dump(data, f, indent=2)

    def update(self):
        logger.info("last_subscription_fetch = %r", self.last_subscription_fetch)
        if self.last_subscription_fetch is None or self.last_events_fetch is None:
            self.initial_fetch()
            self.last_subscription_fetch = self.last_events_fetch = self.now() - datetime.timedelta(minutes=10)
            self.save_data()
            return

        self.apply_events()

        max_date = self.last_subscription_fetch or datetime.datetime(1900, 1, 1, tzinfo=pytz.utc)
        for p in super(OTXv2Cached, self).getall(modified_since=self.last_subscription_fetch, iter=True):
            max_date = max(max_date, pytz.utc.localize(dateutil.parser.parse(p['modified'])))
            logger.info("downloading %r - %r", p['name'], p['modified'])
            self.save_pulse(p)

        self.last_subscription_fetch = max_date
        self.save_data()

    def initial_fetch(self, author_name=None):
        logger.info("Performing initial fetch (author_name=%r)", author_name)
        for p in super(OTXv2Cached, self).getall(
            author_name=author_name, modified_since=self.now() - self.max_age if self.max_age else None, iter=True, limit=100
        ):
            self.save_pulse(p)

    def apply_events(self):
        logging.info("last_events_fetch = %r", self.last_events_fetch)
        max_date = self.last_events_fetch or datetime.datetime(1900, 1, 1, tzinfo=pytz.utc)
        for event in self.getevents_since(timestamp=self.last_events_fetch):
            max_date = max(max_date, pytz.utc.localize(dateutil.parser.parse(event['created'])))
            if event['object_type'] == 'pulse':
                self.apply_pulse_event(event)
            elif event['object_type'] == 'user':
                self.apply_user_event(event)
            elif event['object_type'] == 'group':
                self.apply_group_event(event)
            else:
                logger.error("Unknown/unhandled event type: %r", event)

        self.last_events_fetch = max_date
        self.save_data()

    def apply_pulse_event(self, e):
        if e['action'] == 'subscribe':
            self.save_pulse(self.get_pulse_details(e['object_id']))
        elif e['action'] == 'unsubscribe':
            self.delete_pulse_file(e['object_id'])
        else:
            logger.error("Unknown action in pulse event: {}", e)

    def apply_user_event(self, e):
        if e['action'] == 'subscribe':
            self.initial_fetch(author_name=e['object_id'])
        elif e['action'] == 'unsubscribe':
            to_delete = self.find_pulses(author_names=[e['object_id']])
            for pid in to_delete:
                self.delete_pulse_file(pid)
        else:
            logger.error("Unknown action in user event: {}", e)

    def apply_group_event(self, e):
        pass

    def pulse_cache_dir(self, pulse_id, create=False):
        pulse_dir = os.path.join(self.cache_dir, pulse_id[-1], pulse_id[-2])
        if create and not os.path.exists(pulse_dir):
            os.makedirs(pulse_dir)

        return pulse_dir

    def pulse_file(self, pulse_id, create=False):
        pulse_file = pulse_id + '.json'
        return os.path.join(self.pulse_cache_dir(pulse_id, create=create), pulse_file)

    def save_pulse(self, p):
        logger.info("Saving pulse (id=%r)", p['id'])
        with open(self.pulse_file(p['id'], create=True), 'w') as f:
            json.dump(p, f, indent=2)

    def delete_pulse_file(self, pulse_id):
        logger.info("Deleting pulse cache file (id=%r)", pulse_id)
        pulse_file = self.pulse_file(pulse_id, create=False)
        if os.path.exists(pulse_file):
            os.unlink(pulse_file)

    def load_pulse(self, pulse_id):
        pulse_file = self.pulse_file(pulse_id, create=False)
        if not os.path.exists(pulse_file):
            return None
        with open(pulse_file) as f:
            p = json.load(f)

        return p

    def find_pulses(self, return_type='pulse_id', author_names=None, modified_since=None):
        author_names = set([x.lower() for x in author_names]) if author_names else None
        modified_since = self.fix_date(modified_since)

        for dirName, subdirList, fileList in os.walk(self.cache_dir):
            for fname in fileList:
                if fname == "data.json":
                    continue

                pulse_id = os.path.splitext(fname)[0]
                pulse = None
                if author_names or modified_since or return_type == 'pulse':
                    pulse = self.load_pulse(pulse_id)

                if author_names:
                    if pulse['author_name'].lower() not in author_names:
                        continue

                if modified_since:
                    if self.fix_date(pulse['modified']) < modified_since:
                        continue

                if return_type == 'pulse_id':
                    yield pulse_id
                elif return_type == 'pulse':
                    yield pulse
                else:
                    raise Exception("return_type should be one of ['pulse_id', 'pulse']")

    # FIXME this is unordered...
    def getall(self, modified_since=None, author_name=None, iter=False, limit=None, max_page=None, max_items=None):
        if iter:
            return self.getall_iter(modified_since=modified_since, author_name=author_name, limit=limit, max_page=max_page, max_items=max_items)
        else:
            return list(self.getall_iter(modified_since=modified_since, author_name=author_name, limit=limit, max_page=max_page, max_items=max_items))

    def getall_iter(self, modified_since=None, author_name=None, iter=False, limit=50, max_page=None, max_items=None):
        count = 0
        for p in self.find_pulses(
            modified_since=modified_since,
            author_names=[author_name] if author_name else None,
            return_type='pulse',
        ):
            yield p

            count += 1
            if max_page and count > max_page*limit:
                break

            if max_items and count > max_items:
                break

    def getsince(self, timestamp, limit=50, max_page=None, max_items=None):
        return self.getall(modified_since=timestamp, iter=False, limit=limit, max_page=max_page, max_items=max_items)

    def getsince_iter(self, timestamp, limit=50, max_page=None, max_items=None):
        return self.getall(modified_since=timestamp, iter=True, limit=limit, max_page=max_page, max_items=max_items)

    def get_all_indicators(self, author_name=None, modified_since=None, indicator_types=IndicatorTypes.all_types, limit=50, max_page=None, max_items=None):
        name_list = IndicatorTypes.to_name_list(indicator_types)
        for pulse in self.getall_iter(author_name=author_name, modified_since=modified_since, limit=limit, max_page=max_page, max_items=max_items):
            for indicator in pulse["indicators"]:
                if indicator["type"] in name_list:
                    yield indicator



