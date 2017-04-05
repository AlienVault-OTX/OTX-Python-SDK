import datetime
import json
import os
import pprint
import requests
import string
import time
import unittest

from utils import generate_rand_string
from OTXv2 import OTXv2, InvalidAPIKey, BadRequest, RetryError
import IndicatorTypes


STRP_TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%f'
ALIEN_DEV_SERVER = os.getenv('X_OTX_DEV_SERVER', "")
ALIEN_API_APIKEY = ""


def create_user(username, password, email):
    """
    Create a user, and get the API key
    """
    requests.post(ALIEN_DEV_SERVER + 'otxapi/qatests/setup/', json={"users": [{ "username": username, "password": password, "email": email}]})
    r = requests.post(ALIEN_DEV_SERVER + 'auth/login', json={"username": username, "password": password})
    j = json.loads(r.text)
    r = requests.get(ALIEN_DEV_SERVER + 'otxapi/user/?detailed=true', headers={'Authorization': j['key']})
    j = r.json()
    return j['api_keys'][0]['api_key']


def delete_user(username):
    r = requests.post(ALIEN_DEV_SERVER + 'otxapi/qatests/cleanup/', json={"users":  [username ] })


# Class names should start with "Test"
class TestOTXv2(unittest.TestCase):
    """
    Base class configure API Key to use on a per test basis.
    """
    def setUp(self, api_key=''):
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
        # print(u"test_search_pulses_simple top hit: {0}".format(pulse.get('name', '')))
        self.assertIsNotNone(pulse.get('modified', None))
        self.assertIsNotNone(pulse.get('author', None))
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


class TestPulseCreate(TestOTXv2):
    def test_create_pulse_simple(self):
        name = "Pyclient-simple-unittests-" + generate_rand_string(8, charset=string.hexdigits).lower()
        # print("test_create_pulse_simple submitting pulse: " + name)
        response = self.otx.create_pulse(name=name,
                                         public=False,
                                         indicators=[],
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
        return

    def test_create_pulse_and_update(self):
        """
        Test: create a pulse then replace the indicators
        """
        indicator_list = [ {'indicator': "one.com", 'type': 'domain'} ]
        new_indicators = [ {'indicator': "two.com", 'type': 'domain'} ]
        name = "Pyclient-indicators-unittests-modify-pulse"
        response = self.otx.create_pulse(name=name, public=False, indicators=indicator_list)
        pulse_id = response['id']
        response = self.otx.replace_pulse_indicators(pulse_id, new_indicators)
        new_indicators = str(response['indicators']['indicators'])
        self.assertTrue('two.com' in new_indicators)
        return

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
        return


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
    def test_backoff(self):
        with self.assertRaises(RetryError):
            t1 = time.time()
            self.otx.get('error/500/')
        diff = time.time() - t1
        self.assertTrue(diff > 1+2+4+8+16)

    def test_user_agent(self):
        o = OTXv2(self.api_key, server=ALIEN_DEV_SERVER, project='foo')
        self.assertEqual(o.headers['User-Agent'], 'OTX Python foo/1.1')

        o = OTXv2(self.api_key, server=ALIEN_DEV_SERVER, user_agent='foo')
        self.assertEqual(o.headers['User-Agent'], 'foo')

if __name__ == '__main__':
    username = "qatester-github-temp"
    ALIEN_API_APIKEY = create_user(username, "password", username + "@aveng.us")
    unittest.main()
    delete_user(username)
