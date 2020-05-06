import datetime
import dateutil.parser
import hashlib
import io
import json
import os
import random
import requests
import shutil
import string
import tempfile
import time
import unittest

from utils import generate_rand_string
from OTXv2 import OTXv2, OTXv2Cached, InvalidAPIKey, BadRequest, RetryError, NotFound
import IndicatorTypes
from patch_pulse import PatchPulse


STRP_TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%f'
ALIEN_DEV_SERVER = os.getenv('X_OTX_DEV_SERVER', "")
ALIEN_API_APIKEY = ""

rand = random.randint(0, 1e9)


def create_user(username, password, email, group_ids=None):
    """
    Create a user, and get the API key
    """
    requests.post(ALIEN_DEV_SERVER + 'otxapi/qatests/setup/', json={"users": [
        {"username": username, "password": password, "email": email, "group_ids": group_ids}
    ]})
    r = requests.post(ALIEN_DEV_SERVER + 'auth/login', json={"username": username, "password": password})
    j = json.loads(r.text)
    r = requests.get(ALIEN_DEV_SERVER + 'otxapi/user/?detailed=true', headers={'Authorization': j['key']})
    j = r.json()
    print("creating user {} (key={} groups={})".format(username, j['api_keys'][0]['api_key'],  group_ids))
    return j['api_keys'][0]['api_key']


def delete_user(username):
    print("deleting user {}".format(username))
    r = requests.post(ALIEN_DEV_SERVER + 'otxapi/qatests/cleanup/', json={"users": [username]})
    return r.json()


# Class names should start with "Test"
class TestOTXv2(unittest.TestCase):
    """
    Base class configure API Key to use on a per test basis.
    """
    def setUp(self, api_key=''):
        self.maxDiff = None
        self.api_key = api_key or ALIEN_API_APIKEY
        self.otx = OTXv2(self.api_key, server=ALIEN_DEV_SERVER)


class TestSubscriptionsInvalidKey(TestOTXv2):
    """
    Confirm InvalidAPIKey class is raised for API Key failures
    """
    def setUp(self, **kwargs):
        super(TestSubscriptionsInvalidKey, self).setUp(api_key=generate_rand_string(length=64))

    def test_getall(self):
        with self.assertRaises(InvalidAPIKey):
            r = self.otx.getall(max_page=3, limit=5)


class TestSubscriptions(TestOTXv2):
    """
    Confirm that given a valid API Key, we can obtain threat intelligence subscriptions.
    """

    def test_getall(self):
        pulses = self.otx.getall(max_page=3, limit=5)
        self.assertIsNotNone(pulses)
        self.assertTrue(len(pulses) > 0)
        self.assertTrue(len(pulses) <= 3 * 5)
        most_recent = pulses[0]
        self.assertIsNotNone(most_recent.get('id', None))
        self.assertIsNotNone(most_recent.get('name', None))
        self.assertIsNotNone(most_recent.get('description', None))
        self.assertIsNotNone(most_recent.get('author_name', None))
        self.assertIsNotNone(most_recent.get('indicators', None))
        self.assertIsNotNone(most_recent.get('created', None))
        self.assertIsNotNone(most_recent.get('modified', None))
        self.assertIsNotNone(most_recent.get('id', None))

    def test_getall_iter(self):
        pulse_gen = self.otx.getall_iter(max_page=3, limit=5)
        self.assertIsNotNone(pulse_gen)
        for pulse in pulse_gen:
            # print(u"test_getall_iter next pulse: {0}".format(pulse.get('name', '')))
            self.assertTrue(pulse.get('name', None))

    def test_getsince(self):
        three_months_dt = (datetime.datetime.now() - datetime.timedelta(days=90))
        three_months_timestamp = three_months_dt.isoformat()
        pulses = self.otx.getsince(three_months_timestamp, limit=9999, max_page=3)
        for pulse in pulses:
            # print(u"test_getsince next pulse: {0}".format(pulse.get('name', '')))
            pulse_modified = pulse.get('modified', None)
            self.assertIsNotNone(pulse_modified)
            try:
                pulse_modified_dt = datetime.datetime.strptime(pulse_modified, STRP_TIME_FORMAT)
            except ValueError:
                pulse_modified_dt = datetime.datetime.strptime(pulse_modified, '%Y-%m-%dT%H:%M:%S')
            self.assertGreaterEqual(pulse_modified_dt, three_months_dt)

    def test_getsince_iter(self):
        three_months_dt = (datetime.datetime.now() - datetime.timedelta(days=90))
        three_months_timestamp = three_months_dt.isoformat()
        pulse_gen = self.otx.getsince_iter(three_months_timestamp, limit=9999, max_page=3)
        self.assertIsNotNone(pulse_gen)
        for pulse in pulse_gen:
            # print(u"test_getsince_iter next pulse: {0}".format(pulse.get('name', '')))
            self.assertTrue(pulse.get('name', None))
            pulse_modified = pulse.get('modified', None)
            self.assertIsNotNone(pulse_modified)
            try:
                pulse_modified_dt = datetime.datetime.strptime(pulse_modified, STRP_TIME_FORMAT)
            except ValueError:
                pulse_modified_dt = datetime.datetime.strptime(pulse_modified, '%Y-%m-%dT%H:%M:%S')
            self.assertGreaterEqual(pulse_modified_dt, three_months_dt)

    def test_author_param(self):
        for pulse in self.otx.getall(author_name='AlienVault', max_page=3):
            self.assertEqual(pulse['author_name'], 'AlienVault')

        three_months_dt = (datetime.datetime.now() - datetime.timedelta(days=90))
        for pulse in self.otx.getall(author_name='AlienVault', modified_since=three_months_dt, max_page=3):
            self.assertEqual(pulse['author_name'], 'AlienVault')
            pulse_modified = pulse.get('modified', None)
            try:
                pulse_modified_dt = datetime.datetime.strptime(pulse_modified, STRP_TIME_FORMAT)
            except ValueError:
                pulse_modified_dt = datetime.datetime.strptime(pulse_modified, '%Y-%m-%dT%H:%M:%S')
            self.assertGreaterEqual(pulse_modified_dt, three_months_dt)


class TestSearch(TestOTXv2):
    def test_search_pulses_simple(self):
        res = self.otx.search_pulses("Russian")
        pulses = res.get('results')
        self.assertTrue(len(pulses) > 0)
        self.assertIsNotNone(pulses)
        self.assertTrue(len(pulses) > 0)
        pulse = pulses[0]
        #print(u"test_search_pulses_simple top hit: {0}".format(pulse.get('name', '')))
        #print str(pulses[0])
        self.assertIsNotNone(pulse.get('modified', None))
        self.assertIsNotNone(pulse.get('author_name', None))
        self.assertIsNotNone(pulse.get('id', None))
        self.assertIsNotNone(pulse.get('tags', None))
        self.assertIsNotNone(pulse.get('references', None))
        self.assertIsNotNone(res.get('exact_match'))

    def test_exact_match_domain(self):
        res = self.otx.search_pulses("malware.org")
        pulses = res.get('results')
        self.assertTrue(isinstance(pulses, list))
        self.assertTrue(len(pulses) > 0)
        self.assertIsNotNone(pulses)
        # print("test_exact_match_domain additional data for malware.org:")
        # pprint.pprint(res)
        self.assertTrue(res.get('exact_match', -1))

    def test_search_users(self):
        res = self.otx.search_users("alien")
        self.assertTrue('results' in res.keys())
        self.assertTrue(isinstance(res.get('results', ''), list))
        users = res.get('results')
        first_user = users[0]
        self.assertTrue(first_user.get('username', '') != '')
        self.assertTrue(res.get('count', -1) >= 0)


class TestEvents(TestOTXv2):
    def test_getevents_since(self):
        three_months_dt = (datetime.datetime.now() - datetime.timedelta(days=90))
        three_months_timestamp = three_months_dt.isoformat()
        events = self.otx.getevents_since(three_months_timestamp, limit=9999)
        self.assertIsNotNone(events)
        self.assertTrue(len(events) > 0)
        most_recent = events[0]
        self.assertIsNotNone(most_recent.get('action', None))
        self.assertIsNotNone(most_recent.get('created', None))
        self.assertIsNotNone(most_recent.get('id', None))


class TestIndicatorTypes(TestOTXv2):
    def test_get_all_indicators(self):
        indicator_gen = self.otx.get_all_indicators(max_page=3)
        for indicator in indicator_gen:
            self.assertIsNotNone(indicator)
            self.assertIsNotNone(indicator.get('type', None))
            self.assertIsNotNone(indicator.get('indicator', None))
            self.assertIsNotNone(indicator.get('description', None))

    def test_get_all_ipv4_indicators(self):
        ipv4_type_list = [IndicatorTypes.IPv4]
        ipv4_indicator_gen = self.otx.get_all_indicators(indicator_types=ipv4_type_list, max_page=3)
        for indicator in ipv4_indicator_gen:
            self.assertIsNotNone(indicator)
            self.assertIsNotNone(indicator.get('type', None))
            self.assertIsNotNone(indicator.get('indicator', None))
            self.assertIsNotNone(indicator.get('description', None))
            self.assertTrue(indicator.get('type', '') == IndicatorTypes.IPv4.name)


class TestPulseDetails(TestOTXv2):
    def test_get_pulse_details(self):
        # get a pulse from search to use as testcase
        res = self.otx.search_pulses("Russian")
        pulses = res.get('results')
        self.assertTrue(len(pulses) > 0)
        pulse = pulses[0]
        pulse_id = pulse.get('id', '')
        meta_data = self.otx.get_pulse_details(pulse_id=pulse_id)
        # pprint.pprint(meta_data)
        self.assertIsNotNone(meta_data)
        self.assertTrue('author_name' in meta_data.keys())
        self.assertTrue('name' in meta_data.keys())
        self.assertTrue('references' in meta_data.keys())
        self.assertTrue('tags' in meta_data.keys())
        self.assertTrue('indicators' in meta_data.keys())

    def test_get_pulse_indicators(self):
        res = self.otx.search_pulses("Russian")
        pulses = res.get('results')
        self.assertTrue(len(pulses) > 0)
        pulse = pulses[0]
        pulse_id = pulse.get('id', '')
        indicators = self.otx.get_pulse_indicators(pulse_id=pulse_id)
        self.assertIsNotNone(indicators)
        # print("Indicators is " + str(indicators))
        for indicator in indicators:
            # print("next indicator:")
            # pprint.pprint(indicator)
            self.assertIsNotNone(indicator.get('indicator'))
            self.assertIsNotNone(indicator.get('type'))

    def test_get_pulse_indicators_bad_pulse_id(self):
        with self.assertRaises(NotFound):  # not an existing pulse
            res = self.otx.get_pulse_indicators("a"*24)

        with self.assertRaises(BadRequest):   # not enough characters
            res = self.otx.get_pulse_indicators("aaaaaa")

        with self.assertRaises(BadRequest):   # too many characters
            res = self.otx.get_pulse_indicators("a"*25)

        with self.assertRaises(BadRequest):   # not a string
            res = self.otx.get_pulse_indicators(1)

    def test_get_pulse_indicators_expired(self):
        # create and check pulse
        indicator_list = [
            {'indicator': "one.com", 'type': 'domain'},
            {'indicator': "two.com", 'type': 'domain'},
            {'indicator': "foo@alienvault.com", 'type': 'email'},
            {'indicator': "bar@alienvault.com", 'type': 'email'},
        ]
        name = "Pyclient-indicators-unittests-modify-pulse"
        response = self.otx.create_pulse(name=name, public=False, indicators=indicator_list)
        pulse_id = response['id']

        check_fields = ['indicator', 'type', 'expiration', 'is_active', 'title']
        expected = [
            {'indicator': u'bar@alienvault.com', 'type': u'email',  'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'foo@alienvault.com', 'type': u'email',  'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'one.com',            'type': u'domain', 'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'two.com',            'type': u'domain', 'expiration': None, 'is_active': 1, 'title': u''},
        ]
        ind = self.otx.get_pulse_indicators(pulse_id)
        actual = sorted([{f: x[f] for f in check_fields} for x in ind], key=lambda x: x['indicator'])
        self.assertEqual(expected, actual)

        # set one.com to expired
        to_expire = [x['id'] for x in ind if x['indicator'] == 'one.com']
        self.assertEqual(len(to_expire), 1)
        body = {
            'indicators': {
                'edit': [{'id': i, 'is_active': False} for i in to_expire]
            }
        }
        self.otx.edit_pulse(pulse_id, body=body)

        # should't show up
        expected = [
            {'indicator': u'bar@alienvault.com', 'type': u'email',  'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'foo@alienvault.com', 'type': u'email',  'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'two.com',            'type': u'domain', 'expiration': None, 'is_active': 1, 'title': u''},
        ]
        ind = self.otx.get_pulse_indicators(pulse_id)
        actual = sorted([{f: x[f] for f in check_fields} for x in ind], key=lambda x: x['indicator'])
        self.assertEqual(expected, actual)

        # but it should if we pass include_inactive
        expected = [
            {'indicator': u'bar@alienvault.com', 'type': u'email',  'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'foo@alienvault.com', 'type': u'email',  'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'one.com',            'type': u'domain', 'expiration': None,    'is_active': 0, 'title': u''},
            {'indicator': u'two.com',            'type': u'domain', 'expiration': None,    'is_active': 1, 'title': u''},
        ]
        ind = self.otx.get_pulse_indicators(pulse_id, include_inactive=True)
        actual = sorted([{f: x[f] for f in check_fields} for x in ind], key=lambda x: x['indicator'])
        self.assertEqual(expected, actual)


class TestIndicatorDetails(TestOTXv2):
    def test_get_indicator_details_IPv4_by_section(self):
        # print("test_get_indicator_details_IPv4_by_section")
        for section in IndicatorTypes.IPv4.sections:
            # print("next section: {0}".format(section))
            section_details = self.otx.get_indicator_details_by_section(IndicatorTypes.IPv4, "69.73.130.198", section)
            # print(u"section: {0}".format(section))
            # pprint.pprint(section_details)
            self.assertTrue(True)

    def test_get_indicator_details_IPv4_full(self):
        # print("test_get_indicator_details_IPv4_full")
        full_details = self.otx.get_indicator_details_full(IndicatorTypes.IPv4, "69.73.130.198")
        self.assertTrue(sorted(full_details.keys()) == sorted(IndicatorTypes.IPv4.sections))
        # pprint.pprint(full_details)

    def test_get_indicator_details_Email_full(self):
        # print("test_get_indicator_details_IPv4_full")
        full_details = self.otx.get_indicator_details_full(IndicatorTypes.EMAIL, "me@rustybrooks.com")
        self.assertTrue(sorted(full_details.keys()) == sorted(IndicatorTypes.EMAIL.sections))
        # pprint.pprint(full_details)


class TestPulseCreate(TestOTXv2):
    user1 = "qatester-git-pulse-{}".format(rand)
    otx = None

    @classmethod
    def setUpClass(cls):
        cls.otx2 = OTXv2(create_user(cls.user1, "password", cls.user1 + "@aveng.us", group_ids=[51, 64, 2931]), server=ALIEN_DEV_SERVER)

    @classmethod
    def tearDownClass(cls):
        delete_user(cls.user1)

    def test_create_pulse_simple(self):
        name = "Pyclient-simple-unittests-" + generate_rand_string(8, charset=string.hexdigits).lower()
        # print("test_create_pulse_simple submitting pulse: " + name)
        response = self.otx.create_pulse(name=name,
                                         public=False,
                                         indicators=[{'indicator': "8.8.8.8", 'type': IndicatorTypes.IPv4.name}],
                                         tags=[],
                                         references=[])
        self.assertIsNotNone(response)

    def test_create_pulse_no_name(self):
        """
        Test: pulse without name should raise value error
        """
        # print("test_create_pulse_no_name submitting nameless pulse")
        with self.assertRaises(ValueError):
            self.otx.create_pulse(**{})

    def test_create_pulse_name_too_short(self):
        """
        Test: pulse without name should raise value error
        """
        body = {'name': generate_rand_string(2)}
        # print("test_create_pulse_name_too_short submitting pulse: {}\nExpecting BadRequest.".format(body))
        with self.assertRaises(BadRequest):
            self.otx.create_pulse(**body)

    def test_create_pulse_tlp_mismatch(self):
        """
        Test: pulse without name should raise value error
        """
        name = generate_rand_string(10)
        tlps = ['red', 'amber']
        for tlp in tlps:
            # print("test_create_pulse_tlp_mismatch submitting pulse: {} (tlp: {})".format(name, tlp))
            with self.assertRaises(BadRequest):
                self.otx.create_pulse(name=name, TLP=tlp, public=True)

    def test_create_pulse_with_indicators(self):
        """
        Test: pulse with list of indicators
        """
        charset = string.ascii_letters
        validated_indicator_list = []
        indicator_list = [
            {'indicator': generate_rand_string(10, charset=charset) + ".com", 'type': IndicatorTypes.DOMAIN},
            {'indicator': generate_rand_string(3, charset=charset) + "." + generate_rand_string(10, charset=charset) + ".com", 'type': IndicatorTypes.HOSTNAME},
            {'indicator': "69.73.130.198", 'type': IndicatorTypes.IPv4},
            {'indicator': "2a00:1450:4001:800::1017", 'type': IndicatorTypes.IPv6},
            {'indicator': "spearphish@" + generate_rand_string(10) + ".com", 'type': IndicatorTypes.EMAIL},
            {'indicator': "14c04f88dc97aef3e9b516ef208a2bf5", 'type': IndicatorTypes.FILE_HASH_MD5},
            {'indicator': "48e04cb52f1077b5f5aab75baff6c27b0ee4ade1", 'type': IndicatorTypes.FILE_HASH_SHA1},
            {'indicator': "7522bc3e366c19ab63381bacd0f03eb09980ecb915ada08ae76d8c3e538600de", 'type': IndicatorTypes.FILE_HASH_SHA256},
            {'indicator': "a060fe925aa888053010d1e195ef823a", 'type': IndicatorTypes.FILE_HASH_IMPHASH},
            {'indicator': "\sonas\share\samples\14\c0\4f\88\14c04f88dc97aef3e9b516ef208a2bf5", 'type': IndicatorTypes.FILE_PATH},
        ]
        name = "Pyclient-indicators-unittests-" + generate_rand_string(8, charset=string.hexdigits).lower()
        for indicator in indicator_list:
            validated_indicator = self.otx.validate_indicator(indicator.get('type'), indicator.get('indicator', ''))
            self.assertTrue('success' in validated_indicator.get('status', ''))
            validated_indicator_list.append(validated_indicator)
        # print("test_create_pulse_with_indicators: finished validating indicators.\nsubmitting pulse: {}".format({"name": name, "indicators": validated_indicator_list}))
        response = self.otx.create_pulse(name=name, public=False, indicators=validated_indicator_list)
        self.assertTrue(response.get('name', '') == name)
        self.assertTrue(len(response.get('indicators', [])) == len(validated_indicator_list))

    def test_create_pulse_and_update(self):
        """
        Test: create a pulse then replace the indicators
        """
        indicator_list = [{'indicator': "one.com", 'type': 'domain'}]
        new_indicators = [{'indicator': "two.com", 'type': 'domain'}]
        name = "Pyclient-indicators-unittests-modify-pulse"
        response = self.otx.create_pulse(name=name, public=False, indicators=indicator_list)
        pulse_id = response['id']
        response = self.otx.replace_pulse_indicators(pulse_id, new_indicators)
        new_indicators = str(response['indicators']['indicators'])
        self.assertTrue('two.com' in new_indicators)

    def test_replace_indicators(self):
        indicator_list = [
            {'indicator': "one.com", 'type': 'domain'},
            {'indicator': "two.com", 'type': 'domain'},
            {'indicator': "foo@alienvault.com", 'type': 'email'},
            {'indicator': "bar@alienvault.com", 'type': 'email'},
        ]
        name = "Pyclient-indicators-unittests-modify-pulse"
        response = self.otx.create_pulse(name=name, public=False, indicators=indicator_list)
        pulse_id = response['id']

        check_fields = ['indicator', 'type', 'expiration', 'is_active', 'title']
        expected = [
            {'indicator': u'bar@alienvault.com', 'type': u'email',  'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'foo@alienvault.com', 'type': u'email',  'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'one.com',            'type': u'domain', 'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'two.com',            'type': u'domain', 'expiration': None,    'is_active': 1, 'title': u''},
        ]
        actual = sorted([{f: x[f] for f in check_fields} for x in self.otx.get_pulse_indicators(pulse_id)], key=lambda x: x['indicator'])
        self.assertEqual(expected, actual)

        # add new indicator, don't include one.com which should set it to expired
        new_indicators = [
            {'indicator': "two.com", 'type': 'domain'},
            {'indicator': "three.com", 'type': 'domain'},
            {'indicator': "foo@alienvault.com", 'type': 'email'},
            {'indicator': "bar@alienvault.com", 'type': 'email'},
        ]
        self.otx.replace_pulse_indicators(pulse_id, new_indicators)
        expected = [
            {'indicator': u'bar@alienvault.com', 'type': u'email',  'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'foo@alienvault.com', 'type': u'email',  'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'one.com',            'type': u'domain', 'expiration': 'today', 'is_active': 1, 'title': u'Expired'},
            {'indicator': u'three.com',          'type': u'domain', 'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'two.com',            'type': u'domain', 'expiration': None,    'is_active': 1, 'title': u''},
        ]
        actual = sorted(
            [{f: x[f] for f in check_fields} for x in self.otx.get_pulse_indicators(pulse_id)],
            key=lambda x: x['indicator']
        )
        for a in actual:
            if a['expiration']:
                exp = dateutil.parser.parse(a['expiration'])
                a['expiration'] = 'today' if abs((exp - datetime.datetime.utcnow())).total_seconds() < 60 else a['expiration']
        self.assertEqual(expected, actual)

        # add one.com back, which should reactivate it, and leave two.com out which should expire it
        new_indicators = [
            {'indicator': "one.com", 'type': 'domain', 'title': 'new title'},
            {'indicator': "three.com", 'type': 'domain'},
            {'indicator': "foo@alienvault.com", 'type': 'email'},
            {'indicator': "bar@alienvault.com", 'type': 'email'},
        ]
        self.otx.replace_pulse_indicators(pulse_id, new_indicators)
        expected = [
            {'indicator': u'bar@alienvault.com', 'type': u'email',  'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'foo@alienvault.com', 'type': u'email',  'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'one.com',            'type': u'domain', 'expiration': None,    'is_active': 1, 'title': u'new title'},
            {'indicator': u'three.com',          'type': u'domain', 'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'two.com',            'type': u'domain', 'expiration': 'today', 'is_active': 1, 'title': u'Expired'},
        ]
        actual = sorted(
            [{f: x[f] for f in check_fields} for x in self.otx.get_pulse_indicators(pulse_id)],
            key=lambda x: x['indicator']
        )
        for a in actual:
            if a['expiration']:
                exp = dateutil.parser.parse(a['expiration'])
                a['expiration'] = 'today' if abs((exp - datetime.datetime.utcnow())).total_seconds() < 60 else a['expiration']
        self.assertEqual(expected, actual)

    def test_add_or_update_indicators(self):
        indicator_list = [
            {'indicator': "one.com", 'type': 'domain'},
            {'indicator': "two.com", 'type': 'domain'},
            {'indicator': "foo@alienvault.com", 'type': 'email'},
            {'indicator': "bar@alienvault.com", 'type': 'email'},
            {'indicator': '8.8.8.8', 'type': 'IPv4'}
        ]
        name = "Pyclient-indicators-unittests-modify-pulse"
        response = self.otx.create_pulse(name=name, public=False, indicators=indicator_list)
        pulse_id = response['id']

        check_fields = ['indicator', 'type', 'expiration', 'is_active', 'title']
        expected = [
            {'indicator': u'8.8.8.8',            'type': u'IPv4',   'expiration': 'month', 'is_active': 1, 'title': u''},
            {'indicator': u'bar@alienvault.com', 'type': u'email',  'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'foo@alienvault.com', 'type': u'email',  'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'one.com',            'type': u'domain', 'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'two.com',            'type': u'domain', 'expiration': None,    'is_active': 1, 'title': u''},
        ]
        actual = sorted([{f: x[f] for f in check_fields} for x in self.otx.get_pulse_indicators(pulse_id, include_inactive=True)], key=lambda x: x['indicator'])
        for a in actual:
            if a['expiration']:
                exp = dateutil.parser.parse(a['expiration'])
                a['expiration'] = 'month' if 60*60*24*27 < abs((exp - datetime.datetime.utcnow())).total_seconds() < 60*60*24*32 else a['expiration']
        self.assertEqual(expected, actual)

        # add some indicators and update others.  omitted indicators should stay same
        indicators = [
            {'indicator': "two.com", 'type': 'domain'},  # no change
            {'indicator': "three.com", 'type': 'domain'},  # new indicator
            {'indicator': "one.com", 'type': 'domain', 'title': 'one.com title'}, # change title
        ]
        self.otx.add_or_update_pulse_indicators(pulse_id, indicators)
        expected = [
            {'indicator': u'8.8.8.8',            'type': u'IPv4',   'expiration': 'month', 'is_active': 1, 'title': u''},
            {'indicator': u'bar@alienvault.com', 'type': u'email',  'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'foo@alienvault.com', 'type': u'email',  'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'one.com',            'type': u'domain', 'expiration': None,    'is_active': 1,  'title': u'one.com title'},
            {'indicator': u'three.com',          'type': u'domain', 'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'two.com',            'type': u'domain', 'expiration': None,    'is_active': 1, 'title': u''},
        ]
        actual = sorted([{f: x[f] for f in check_fields} for x in self.otx.get_pulse_indicators(pulse_id, include_inactive=True)], key=lambda x: x['indicator'])
        for a in actual:
            if a['expiration']:
                exp = dateutil.parser.parse(a['expiration'])
                a['expiration'] = 'month' if 60*60*24*27 < abs((exp - datetime.datetime.utcnow())).total_seconds() < 60*60*24*32 else a['expiration']
        self.assertEqual(expected, actual)

        # expire an indicator
        indicators = [
            {'indicator': u'8.8.8.8', 'is_active': 0},
        ]
        self.otx.add_or_update_pulse_indicators(pulse_id, indicators)
        expected = [
            {'indicator': u'8.8.8.8',            'type': u'IPv4',   'expiration': 'month', 'is_active': 0, 'title': u''},
            {'indicator': u'bar@alienvault.com', 'type': u'email',  'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'foo@alienvault.com', 'type': u'email',  'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'one.com',            'type': u'domain', 'expiration': None,    'is_active': 1,  'title': u'one.com title'},
            {'indicator': u'three.com',          'type': u'domain', 'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'two.com',            'type': u'domain', 'expiration': None,    'is_active': 1, 'title': u''},
        ]
        actual = sorted([{f: x[f] for f in check_fields} for x in self.otx.get_pulse_indicators(pulse_id, include_inactive=True)], key=lambda x: x['indicator'])
        for a in actual:
            if a['expiration']:
                exp = dateutil.parser.parse(a['expiration'])
                a['expiration'] = 'month' if 60*60*24*27 < abs((exp - datetime.datetime.utcnow())).total_seconds() < 60*60*24*32 else a['expiration']
        self.assertEqual(expected, actual)

        # set a new expiration
        new_expiration = (datetime.datetime.utcnow().replace(microsecond=0) + datetime.timedelta(days=14)).isoformat()
        indicators = [
            {'indicator': u'8.8.8.8', 'expiration': new_expiration},
        ]
        self.otx.add_or_update_pulse_indicators(pulse_id, indicators)
        expected = [
            {'indicator': u'8.8.8.8',            'type': u'IPv4',   'expiration': new_expiration, 'is_active': 1, 'title': u''},
            {'indicator': u'bar@alienvault.com', 'type': u'email',  'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'foo@alienvault.com', 'type': u'email',  'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'one.com',            'type': u'domain', 'expiration': None,    'is_active': 1,  'title': u'one.com title'},
            {'indicator': u'three.com',          'type': u'domain', 'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'two.com',            'type': u'domain', 'expiration': None,    'is_active': 1, 'title': u''},
        ]
        actual = sorted([{f: x[f] for f in check_fields} for x in self.otx.get_pulse_indicators(pulse_id, include_inactive=True)], key=lambda x: x['indicator'])
        self.assertEqual(expected, actual)

    def test_remove_indicators(self):
        check_fields = ['indicator', 'type', 'expiration', 'is_active', 'title']

        # make pulse 1 and verify contents
        indicator_list1 = [
            {'indicator': "one.com", 'type': 'domain'},
            {'indicator': "two.com", 'type': 'domain'},
            {'indicator': "foo@alienvault.com", 'type': 'email'},
            {'indicator': "bar@alienvault.com", 'type': 'email'},
        ]
        name1 = "Pyclient-indicators-unittests-modify-pulse1"
        response = self.otx.create_pulse(name=name1, public=False, indicators=indicator_list1)
        pulse_id1 = response['id']
        ind1 = self.otx.get_pulse_indicators(pulse_id1)

        expected = [
            {'indicator': u'bar@alienvault.com', 'type': u'email',  'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'foo@alienvault.com', 'type': u'email',  'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'one.com',            'type': u'domain', 'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'two.com',            'type': u'domain', 'expiration': None,    'is_active': 1, 'title': u''},
        ]
        actual = sorted([{f: x[f] for f in check_fields} for x in ind1], key=lambda x: x['indicator'])
        self.assertEqual(expected, actual)

        # make pulse 2 and verify contents
        indicator_list2 = [
            {'indicator': "one.com", 'type': 'domain'},
            {'indicator': "two.com", 'type': 'domain'},
            {'indicator': "baz@alienvault.com", 'type': 'email'},
        ]
        name2 = "Pyclient-indicators-unittests-modify-pulse1"
        response = self.otx.create_pulse(name=name2, public=False, indicators=indicator_list2)
        pulse_id2 = response['id']
        ind2 = self.otx.get_pulse_indicators(pulse_id2)

        expected = [
            {'indicator': u'baz@alienvault.com', 'type': u'email',  'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'one.com',            'type': u'domain', 'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'two.com',            'type': u'domain', 'expiration': None,    'is_active': 1, 'title': u''},
        ]
        actual = sorted([{f: x[f] for f in check_fields} for x in ind2], key=lambda x: x['indicator'])
        self.assertEqual(expected, actual)

        # determine indicator ids to remove
        to_rem1 = [x['id'] for x in ind1 if x['indicator'] in ['one.com', 'two.com']]
        self.otx.remove_pulse_indicators(pulse_id=pulse_id1, indicator_ids=to_rem1)

        # check that pulse 1 has those indicators removed
        expected = [
            {'indicator': u'bar@alienvault.com', 'type': u'email',  'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'foo@alienvault.com', 'type': u'email',  'expiration': None,    'is_active': 1, 'title': u''},
        ]
        actual = sorted([{f: x[f] for f in check_fields} for x in self.otx.get_pulse_indicators(pulse_id1)], key=lambda x: x['indicator'])
        self.assertEqual(expected, actual)

        # check that pulse 2 has same indicators as before
        expected = [
            {'indicator': u'baz@alienvault.com', 'type': u'email',  'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'one.com',            'type': u'domain', 'expiration': None,    'is_active': 1, 'title': u''},
            {'indicator': u'two.com',            'type': u'domain', 'expiration': None,    'is_active': 1, 'title': u''},
        ]
        actual = sorted([{f: x[f] for f in check_fields} for x in self.otx.get_pulse_indicators(pulse_id2)], key=lambda x: x['indicator'])
        self.assertEqual(expected, actual)

    def test_create_pulse_and_edit(self):
        """
        Test: create a pulse then add indicators via json directly
        """
        indicator_list = [ {'indicator': "one.com", 'type': 'domain'} ]
        indicators_to_add = [ {'indicator': "added.com", 'type': 'domain'} ]
        add_indicators = { 'indicators': { 'add': indicators_to_add } }
        name = "Pyclient-indicators-unittests-modify-pulse"
        response = self.otx.create_pulse(name=name, public=False, indicators=indicator_list)
        pulse_id = response['id']
        response = self.otx.edit_pulse(pulse_id, add_indicators)
        new_indicators = str(response['indicators']['indicators'])
        self.assertTrue('added.com' in new_indicators)

    def test_create_pulse_and_edit_via_patch_pulse(self):
        """
        Test: create a pulse then add indicators via a patch pulse object
        """
        indicator_list = [ {'indicator': "one.com", 'type': 'domain'} ]
        name = "Pyclient-indicators-unittests-modify-pulse-patch-pulse"
        response = self.otx.create_pulse(name=name, public=False, indicators=indicator_list)
        pulse_id = response['id']

        # Edit the pulse using a patch pulse object
        # We could also edit indicators etc. here
        pp = PatchPulse(pulse_id)
        pp.add("tags", ["addtag1", "addtag2"])
        pp.set("description","New Description")

        response = self.otx.edit_pulse(pulse_id, pp.getBody())
        new_tags = str(response['tags'])
        self.assertTrue('addtag1' in new_tags)

    def test_create_pulse_tlp(self):
        """
        Test: pulse with each TLP.
        """
        charset = string.ascii_letters
        indicator_list = [
            {'indicator': generate_rand_string(10, charset=charset) + ".com", 'type': IndicatorTypes.DOMAIN.name, 'description': 'evil domain (unittests)'},
            {'indicator': generate_rand_string(3, charset=charset) + "." + generate_rand_string(10, charset=charset) + ".com", 'type': IndicatorTypes.HOSTNAME.name, 'description': 'evil hostname (unittests)'}
        ]
        name = "Pyclient-tlp-unittests-" + generate_rand_string(8, charset=string.hexdigits).lower()
        tlps = ['red', 'amber', 'green', 'white']
        for tlp in tlps:
            # print("test_create_pulse_tlp: submitting pulse: {}".format({"name": name, "tlp": tlp}))
            response = self.otx.create_pulse(name=name, public=False, tlp=tlp, indicators=indicator_list)
            self.assertTrue(response.get('name', '') == name)
            self.assertTrue(response.get('TLP', '') == tlp)
            self.assertFalse(response.get('public'))

    def test_create_pulse_groups(self):
        """
        Test: pulse with different sets of group ids
        Test user needs to be a member of the groups used in this test: 64, 51 and 2931
        Additionall we will use the test groups 1 and 2, that it is NOT a member of
        """

        charset = string.ascii_letters
        indicator_list = [
            {'indicator': generate_rand_string(10, charset=charset) + ".com", 'type': IndicatorTypes.DOMAIN.name, 'description': 'evil domain (unittests)'},
            {'indicator': generate_rand_string(3, charset=charset) + "." + generate_rand_string(10, charset=charset) + ".com", 'type': IndicatorTypes.HOSTNAME.name, 'description': 'evil hostname (unittests)'}
        ]

        for groups, expected in [
            ([], []),
            (None, []),
            ([1, 51], 'error'),  # Not a member of group 1
            ([64, 51], 'error'),  # we're in both groups but can't post to 64
            ([1], 'error'),
            ([51], [51]),
            ([51, 2931], [51, 2931]),
        ]:
            name = "Pyclient-tlp-unittests-" + generate_rand_string(8, charset=string.hexdigits).lower()
            if expected == 'error':
                with self.assertRaises(BadRequest):
                    self.otx2.create_pulse(name=name, indicators=indicator_list, group_ids=groups)
            else:
                response = self.otx2.create_pulse(name=name, indicators=indicator_list, group_ids=groups)

                self.assertEqual(response.get('name', ''), name)
                self.assertEqual(response.get('group_ids'), expected)

    def test_more_params(self):
        response = self.otx.create_pulse(
            name="Pyclient-params-unittests-" + generate_rand_string(8, charset=string.hexdigits).lower(),
            indicators= [
                {'indicator': generate_rand_string(10) + ".com", 'type': IndicatorTypes.DOMAIN.name, 'description': 'evil domain (unittests)'},
            ],   
            industries=["Industry1", "Industry2"],
            targeted_countries=["Afghanistan", "Anguilla"],
            malware_families=["Backdoor:Linux/Netbus", "Backdoor:Linux/Cyrax"],
            attack_ids=["T1000", "T1486"],
            adversary="APT 1",
        )

        check_fields = ['industries', 'targeted_countries', 'malware_families', 'attack_ids', 'adversary', 'group_ids']
        self.assertEqual({k: response[k] for k in check_fields}, {
            u'adversary': u'APT 1',
            u'attack_ids': [u'T1000', u'T1486'],
            u'group_ids': [],
            u'industries': [u'Industry1', u'Industry2'],
            u'malware_families': [u'Backdoor:Linux/Netbus', u'Backdoor:Linux/Cyrax'],
            u'targeted_countries': [u'Afghanistan', u'Anguilla'],
         })

    def test_clone_pulse(self):
        indicator_list = [
            {'indicator': "one.com", 'type': 'domain'},
            {'indicator': "two.com", 'type': 'domain'},
            {'indicator': "foo@alienvault.com", 'type': 'email'},
            {'indicator': "bar@alienvault.com", 'type': 'email'},
        ]

        # First clone public pulse
        name = "Pyclient-indicators-unittests-clone-pulse"
        response = self.otx.create_pulse(name=name, public=True, indicators=indicator_list)
        pulse_id = response['id']
        print("pulse_id={}".format(pulse_id))

        r = self.otx.clone_pulse(pulse_id, new_name='Cloned pulse')
        new_id = r.pop('id')
        self.assertEqual(r, {
            'detail': 'clone successful.'
        })
        np = self.otx.get_pulse_details(new_id)
        self.assertEqual(
            sorted([x['indicator'] for x in np['indicators']]),
            ['bar@alienvault.com', 'foo@alienvault.com', 'one.com', 'two.com']
        )
        self.assertEqual(np['name'], 'Cloned pulse')

    def test_group_add_remove_pulse(self):
        indicator_list = [
            {'indicator': "one.com", 'type': 'domain'},
        ]
        name = "Pyclient-indicators-unittests-add-remove-pulse"
        response = self.otx.create_pulse(name=name, public=True, indicators=indicator_list)
        pulse_id = response['id']

        for group_id, expected in [
            (1, 'error'),  # Not a member of group 1
            (51, [51]),
            (2931, [51, 2931]),
            (-51, [2931]),
            (-2931, []),
        ]:
            if expected == 'error':
                with self.assertRaises(InvalidAPIKey):
                    if group_id > 0:
                        self.otx2.group_add_pulse(group_id, pulse_id)
                    else:
                        self.otx2.group_remove_pulse(-1*group_id, pulse_id)
            else:
                if group_id > 0:
                    response = self.otx2.group_add_pulse(group_id, pulse_id)
                else:
                    response = self.otx2.group_remove_pulse(-1*group_id, pulse_id)

                self.assertEquals(response, {'status': 'success'})
                d = self.otx2.get_pulse_details(pulse_id)
                self.assertEqual(sorted([x['id'] for x in d['groups']]), expected)


class TestPulseCreateInvalidKey(TestOTXv2):
    def setUp(self, **kwargs):
        super(TestPulseCreateInvalidKey, self).setUp(**{'api_key': "ALIEN_API_APIKEY"})

    def test_create_pulse_invalid_key(self):
        name = "Pyclient-unittests-" + generate_rand_string(8, charset=string.hexdigits).lower()
        # print("test_create_pulse_simple submitting pulse: " + name)
        with self.assertRaises(InvalidAPIKey):
            self.otx.create_pulse(name=name,
                                  public=False,
                                  indicators=[],
                                  tags=[],
                                  references=[])



class TestSubscription(unittest.TestCase):
    user1 = "qatester-git-sub1-{}".format(rand)
    user2 = "qatester-git-sub2-{}".format(rand)
    otx = {}

    @classmethod
    def setUpClass(cls):
        for u in [cls.user1, cls.user2]:
            cls.otx[u] = OTXv2(create_user(u, "password", u + "@aveng.us"), server=ALIEN_DEV_SERVER)

    @classmethod
    def tearDownClass(cls):
        for u in [cls.user1, cls.user2]:
            delete_user(u)

    def test_user_subscription(self):
        check_cols = ['username', 'request_user_is_me', 'request_user_is_following', 'request_user_is_subscribed']
        before_u1 = {k: v for k, v in self.otx[self.user1].get_user(self.user1).items() if k in check_cols}
        before_u2 = {k: v for k, v in self.otx[self.user1].get_user(self.user2).items() if k in check_cols}
        self.assertDictEqual(before_u1, {
            u"username": self.user1, u"request_user_is_me": True, u"request_user_is_subscribed": False, u"request_user_is_following": False,
        })
        self.assertDictEqual(before_u2, {
            u"username": self.user2, u"request_user_is_me": False, u"request_user_is_subscribed": False, u"request_user_is_following": False,
        })

        # sub to u2
        self.otx[self.user1].subscribe_to_user(self.user2)
        after_u1 = {k: v for k, v in self.otx[self.user1].get_user(self.user1).items() if k in check_cols}
        after_u2 = {k: v for k, v in self.otx[self.user1].get_user(self.user2).items() if k in check_cols}
        self.assertDictEqual(after_u1, {
            u"username": self.user1, u"request_user_is_me": True, u"request_user_is_subscribed": False, u"request_user_is_following": False,
        })
        self.assertDictEqual(after_u2, {
            u"username": self.user2, u"request_user_is_me": False, u"request_user_is_subscribed": True, u"request_user_is_following": False,
        })

        # follow u2
        self.otx[self.user1].follow_user(self.user2)
        after2_u1 = {k: v for k, v in self.otx[self.user1].get_user(self.user1).items() if k in check_cols}
        after2_u2 = {k: v for k, v in self.otx[self.user1].get_user(self.user2).items() if k in check_cols}
        self.assertDictEqual(after2_u1, {
            u"username": self.user1, u"request_user_is_me": True, u"request_user_is_subscribed": False, u"request_user_is_following": False,
        })
        self.assertDictEqual(after2_u2, {
            u"username": self.user2, u"request_user_is_me": False, u"request_user_is_subscribed": True, u"request_user_is_following": True,
        })

        # unsub u2
        self.otx[self.user1].unsubscribe_from_user(self.user2)
        after3_u1 = {k: v for k, v in self.otx[self.user1].get_user(self.user1).items() if k in check_cols}
        after3_u2 = {k: v for k, v in self.otx[self.user1].get_user(self.user2).items() if k in check_cols}
        self.assertDictEqual(after3_u1, {
            u"username": self.user1, u"request_user_is_me": True, u"request_user_is_subscribed": False, u"request_user_is_following": False,
        })
        self.assertDictEqual(after3_u2, {
            u"username": self.user2, u"request_user_is_me": False, u"request_user_is_subscribed": False, u"request_user_is_following": True,
        })

        # unfollow u2
        self.otx[self.user1].unfollow_user(self.user2)
        after4_u1 = {k: v for k, v in self.otx[self.user1].get_user(self.user1).items() if k in check_cols}
        after4_u2 = {k: v for k, v in self.otx[self.user1].get_user(self.user2).items() if k in check_cols}
        self.assertDictEqual(after4_u1, {
            u"username": self.user1, u"request_user_is_me": True, u"request_user_is_subscribed": False, u"request_user_is_following": False,
        })
        self.assertDictEqual(after4_u2, {
            u"username": self.user2, u"request_user_is_me": False, u"request_user_is_subscribed": False, u"request_user_is_following": False,
        })

    def test_pulse_subscription(self):
        indicator_list = [{'indicator': "one.com", 'type': 'domain'}]
        name = "subscription test"
        response = self.otx[self.user1].create_pulse(name=name, public=False, indicators=indicator_list)
        pulse_id = response['id']

        before = self.otx[self.user1].get_pulse_details(pulse_id)
        self.assertFalse(before['is_subscribing'])
        self.otx[self.user1].subscribe_to_pulse(pulse_id)
        after = self.otx[self.user1].get_pulse_details(pulse_id)
        self.assertTrue(after['is_subscribing'])
        self.otx[self.user1].unsubscribe_from_pulse(pulse_id)
        after2 = self.otx[self.user1].get_pulse_details(pulse_id)
        self.assertFalse(after2['is_subscribing'])



class TestValidateIndicator(TestOTXv2):
    def test_validate_valid_domain(self):
        indicator = generate_rand_string(8, charset=string.ascii_letters).lower() + ".com"
        indicator_type = IndicatorTypes.DOMAIN
        # print("test_validate_valid_domain submitting (valid-ish) indicator: " + indicator)
        response = self.otx.validate_indicator(indicator_type=indicator_type, indicator=indicator)
        # print("test_validate_valid_domain response: {}".format(response))
        self.assertIsNotNone(response)
        self.assertTrue('success' in response.get('status', ''))

    def test_validate_invalid_domain(self):
        indicator = generate_rand_string(8, charset=string.ascii_letters).lower()
        indicator_type = IndicatorTypes.DOMAIN
        # print("test_validate_invalid_domain submitting indicator: " + indicator)
        with self.assertRaises(BadRequest):
            self.otx.validate_indicator(indicator_type=indicator_type, indicator=indicator)


class TestRequests(TestOTXv2):
    def _test_backoff(self):
        with self.assertRaises(RetryError):
            t1 = time.time()
            self.otx.get('error/500/')
        diff = time.time() - t1
        self.assertTrue(diff > 1+2+4+8+16)

    def test_user_agent(self):
        o = OTXv2(self.api_key, server=ALIEN_DEV_SERVER, project='foo')
        self.assertEqual(o.headers['User-Agent'], 'OTX Python foo/1.5.9')

        o = OTXv2(self.api_key, server=ALIEN_DEV_SERVER, user_agent='foo')
        self.assertEqual(o.headers['User-Agent'], 'foo')


class TestSubmissions(TestOTXv2):
    rand1 = None
    rand2 = None
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.rand1 = random.randint(0, 1e12)
        cls.rand2 = random.randint(0, 1e12)

    def test_submit_file(self):
        data = "print('{} {}')".format(self.rand1, self.rand2)
        try:
            contents = bytes(data, encoding='utf8')
        except TypeError:
            contents = bytes(data)

        filename = 'test{}.py'.format(self.rand1)
        r = self.otx.submit_file(filename=filename, file_handle=io.BytesIO(contents))
        self.assertDictEqual(r, {
            u'result': u'added',
            u'sha256': hashlib.sha256(contents).hexdigest(),
            u'status': u'ok',
        })

        r = self.otx.submitted_files()
        self.assertEqual(r[0]['file_name'], filename)

    def test_submit_url(self):
        time.sleep(2)
        u = "http://flannelcat.rustybrooks.com/xxx/{}".format(self.rand1)
        r = self.otx.submit_url(url=u)
        self.assertDictEqual(r, {u'result': u'added', u'status': u'ok'})

        r = self.otx.submitted_urls()
        self.assertEquals(r[0]['url'], u)

    def test_submit_urls(self):
        time.sleep(2)
        u1 = "http://flannelcat.rustybrooks.com/yyy/{}".format(self.rand1)
        u2 = "http://flannelcat.rustybrooks.com/yyy/{}".format(self.rand2)
        r = self.otx.submit_urls(urls=[u1, u2])
        r['added'].sort()
        self.assertDictEqual(r, {
            u'added': sorted([u2, u1]),
            u'exists': [],
            u'skipped': [],
            u'updated': [],
            u'invalid': [],
            u'status': u'ok',
        })

        r = self.otx.submitted_urls()
        self.assertEquals(
            sorted([x['url'] for x in r[:2]]),
            sorted([u1, u2])
        )


class TestOTXv2Cached(unittest.TestCase):
    user = "qatester-git-u1-{}".format(rand)
    author1 = "qatester-gith-a1-{}".format(rand)
    author2 = "qatester-gith-a2-{}".format(rand)
    otx = {}

    @classmethod
    def setUpClass(cls):

        for u in [cls.user, cls.author1, cls.author2]:
            cls.otx[u] = OTXv2Cached(
                create_user(u, "password", u + "@aveng.us"),
                cache_dir=tempfile.mkdtemp(),
                server=ALIEN_DEV_SERVER,
            )

    @classmethod
    def tearDownClass(cls):
        for u in [cls.user, cls.author1, cls.author2]:
            delete_user(u)
            shutil.rmtree(cls.otx[u].cache_dir)

    def test_basic(self):
        def _names(pulses):
            return sorted([x['name'] for x in pulses])

        def _ind(indicators):
            return sorted([x['indicator'] for x in indicators])

        t1 = datetime.datetime.utcnow(), datetime.datetime.utcnow()

        # new user, no subs except the default, AV.  Unsub from AV user and feed should be empty
        self.otx[self.user].unsubscribe_from_user("AlienVault")

        self.otx[self.user].update()
        t2 = self.otx[self.user].last_subscription_fetch, self.otx[self.user].last_events_fetch
        self.assertEqual(self.otx[self.user].getall(), [])
        self.assertEqual(self.otx[self.user].getall(author_name=self.author1), [])
        self.assertEqual(self.otx[self.user].getall(author_name=self.author2), [])
        self.assertEqual(self.otx[self.user].getall(modified_since=t1[0]), [])
        self.assertEqual(list(self.otx[self.user].get_all_indicators(modified_since=t1[0])), [])

        # let's have the user create a pulse and verify that it shows in their feed
        self.otx[self.user].create_pulse(
            name="xxup1",
            public=True,
            indicators=[{'indicator': "8.8.8.8", 'type': IndicatorTypes.IPv4.name}],
        )

        # let's have author1 create a pulse - we're not subbed to him so it won't show at first
        self.otx[self.author1].create_pulse(
            name="xa1p1",
            public=True,
            indicators=[{'indicator': "9.9.9.9", 'type': IndicatorTypes.IPv4.name}],
        )

        # let's have author2 create a pulse - we're not subbed to him so it won't show at first
        self.otx[self.author2].create_pulse(
            name="xa2p1",
            public=True,
            indicators=[{'indicator': "9.9.9.10", 'type': IndicatorTypes.IPv4.name}],
        )

        self.otx[self.user].update()
        t3 = self.otx[self.user].last_subscription_fetch, self.otx[self.user].last_events_fetch
        self.assertEqual(_names(self.otx[self.user].getall()), ['xxup1'])
        self.assertEqual(_names(self.otx[self.user].getall(author_name=self.author1)), [])
        self.assertEqual(_names(self.otx[self.user].getall(author_name=self.author2)), [])
        self.assertEqual(_names(self.otx[self.user].getall(modified_since=t1[0])), ['xxup1'])
        self.assertEqual(_ind(list(self.otx[self.user].get_all_indicators(modified_since=t1[0]))), ['8.8.8.8'])

        # subscribe to author1, now we should see his pulse
        self.otx[self.user].subscribe_to_user(self.author1)

        self.otx[self.user].update()
        t4 = self.otx[self.user].last_subscription_fetch, self.otx[self.user].last_events_fetch
        self.assertEqual(_names(self.otx[self.user].getall()), ['xa1p1', 'xxup1'])
        self.assertEqual(_names(self.otx[self.user].getall(author_name=self.author1)), ['xa1p1'])
        self.assertEqual(_names(self.otx[self.user].getall(author_name=self.author2)), [])
        self.assertEqual(_names(self.otx[self.user].getall(modified_since=t1[0])), ['xa1p1', 'xxup1'])
        self.assertEqual(_ind(list(self.otx[self.user].get_all_indicators(modified_since=t1[0]))), ['8.8.8.8', '9.9.9.9'])

        # subscribe to author2, now we should see his pulse
        self.otx[self.user].subscribe_to_user(self.author2)

        self.otx[self.user].update()
        t4 = self.otx[self.user].last_subscription_fetch, self.otx[self.user].last_events_fetch
        self.assertEqual(_names(self.otx[self.user].getall()), ['xa1p1', 'xa2p1', 'xxup1'])
        self.assertEqual(_names(self.otx[self.user].getall(author_name=self.author1)), ['xa1p1'])
        self.assertEqual(_names(self.otx[self.user].getall(author_name=self.author2)), ['xa2p1'])
        self.assertEqual(_names(self.otx[self.user].getall(modified_since=t1[0])), ['xa1p1', 'xa2p1', 'xxup1'])
        self.assertEqual(_ind(list(self.otx[self.user].get_all_indicators(modified_since=t1[0]))), ['8.8.8.8', '9.9.9.10', '9.9.9.9'])

        # let's have author2 create another pulse
        self.otx[self.author2].create_pulse(
            name="xa2p2",
            public=True,
            indicators=[{'indicator': "foo.com", 'type': IndicatorTypes.DOMAIN.name}],
        )

        self.otx[self.user].update()
        t5 = self.otx[self.user].last_subscription_fetch, self.otx[self.user].last_events_fetch
        self.assertEqual(_names(self.otx[self.user].getall()), ['xa1p1', 'xa2p1', 'xa2p2', 'xxup1'])
        self.assertEqual(_names(self.otx[self.user].getall(author_name=self.author1)), ['xa1p1'])
        self.assertEqual(_names(self.otx[self.user].getall(author_name=self.author2)), ['xa2p1', 'xa2p2'])
        self.assertEqual(_names(self.otx[self.user].getall(modified_since=t1[0])), ['xa1p1', 'xa2p1', 'xa2p2', 'xxup1'])
        self.assertEqual(_ind(list(self.otx[self.user].get_all_indicators(modified_since=t1[0]))), ['8.8.8.8', '9.9.9.10', '9.9.9.9', 'foo.com'])

        self.assertEqual(_ind(list(self.otx[self.user].get_all_indicators(modified_since=t4[0]))), ['9.9.9.10', 'foo.com'])

        self.assertEqual(_ind(list(self.otx[self.user].get_all_indicators(indicator_types=[IndicatorTypes.DOMAIN]))), ['foo.com'])
        self.assertEqual(_ind(list(self.otx[self.user].get_all_indicators(author_name=self.author1))), ['9.9.9.9'])
        self.assertEqual(_ind(list(self.otx[self.user].get_all_indicators(author_name=self.author2))), ['9.9.9.10', 'foo.com'])
        self.assertEqual(_ind(list(self.otx[self.user].get_all_indicators(author_name=self.author1, indicator_types=[IndicatorTypes.DOMAIN]))), [])
        self.assertEqual(_ind(list(self.otx[self.user].get_all_indicators(author_name=self.author2, indicator_types=[IndicatorTypes.DOMAIN]))), ['foo.com'])

    def test_passthrough(self):
        """
        A simple test that demonstrates that any function not in OTXv2Cached will flow through to it's parent class
        """
        res = self.otx[self.user].search_pulses("Russian")
        pulses = res.get('results')
        self.assertTrue(len(pulses) > 0)
        self.assertIsNotNone(pulses)
        self.assertTrue(len(pulses) > 0)
        pulse = pulses[0]
        self.assertIsNotNone(pulse.get('modified', None))
        self.assertIsNotNone(pulse.get('author_name', None))
        self.assertIsNotNone(pulse.get('id', None))
        self.assertIsNotNone(pulse.get('tags', None))
        self.assertIsNotNone(pulse.get('references', None))
        self.assertIsNotNone(res.get('exact_match'))


if __name__ == '__main__':
    username = "qatester-git-{}".format(rand)

    try:
        ALIEN_API_APIKEY = create_user(username, "password", username + "@aveng.us")
        unittest.main()
    finally:
        print(delete_user(username))
