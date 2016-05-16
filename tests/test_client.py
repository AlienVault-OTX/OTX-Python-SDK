import unittest
import datetime
import os
import pprint
import string

from utils import generate_rand_string
from OTXv2 import OTXv2, InvalidAPIKey
import IndicatorTypes

ALIEN_API_APIKEY = os.getenv('X_OTX_API_KEY', "mysecretkey")
STRP_TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%f'


# Class names should start with "Test"
class TestOTXv2(unittest.TestCase):
    """
    Base class configure API Key to use on a per test basis.
    """
    def setUp(self, **kwargs):
        provided_key = kwargs.get('api_key', '')
        if provided_key:
            self.api_key = provided_key
        else:
            self.api_key = ALIEN_API_APIKEY
        self.otx = OTXv2(self.api_key)


class TestSubscriptionsInvalidKey(TestOTXv2):
    """
    Confirm InvalidAPIKey class is raised for API Key failures
    """
    def setUp(self, **kwargs):
        super(TestSubscriptionsInvalidKey, self).setUp(**{'api_key': generate_rand_string(length=64)})

    def test_getall(self):
        with self.assertRaises(InvalidAPIKey):
            self.otx.getall()


class TestSubscriptions(TestOTXv2):
    """
    Confirm that given a valid API Key, we can obtain threat intelligence subscriptions.
    """
    def setUp(self, **kwargs):
        super(TestSubscriptions, self).setUp(**{'api_key': ALIEN_API_APIKEY})

    def test_getall(self):
        pulses = self.otx.getall()
        self.assertIsNotNone(pulses)
        self.assertTrue(len(pulses) > 0)
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
        pulse_gen = self.otx.getall_iter()
        self.assertIsNotNone(pulse_gen)
        for pulse in pulse_gen:
            print(u"test_getall_iter next pulse: {0}".format(pulse.get('name', '')))
            self.assertTrue(pulse.get('name', None))

    def test_getsince(self):
        three_months_dt = (datetime.datetime.now() - datetime.timedelta(days=90))
        three_months_timestamp = three_months_dt.isoformat()
        pulses = self.otx.getsince(three_months_timestamp, limit=9999)
        for pulse in pulses:
            print(u"test_getsince next pulse: {0}".format(pulse.get('name', '')))
            pulse_modified = pulse.get('modified', None)
            self.assertIsNotNone(pulse_modified)
            pulse_modified_dt = datetime.datetime.strptime(pulse_modified, STRP_TIME_FORMAT)
            self.assertGreaterEqual(pulse_modified_dt, three_months_dt)

    def test_getsince_iter(self):
        three_months_dt = (datetime.datetime.now() - datetime.timedelta(days=90))
        three_months_timestamp = three_months_dt.isoformat()
        pulse_gen = self.otx.getsince_iter(three_months_timestamp, limit=9999)
        self.assertIsNotNone(pulse_gen)
        for pulse in pulse_gen:
            print(u"test_getsince_iter next pulse: {0}".format(pulse.get('name', '')))
            self.assertTrue(pulse.get('name', None))
            pulse_modified = pulse.get('modified', None)
            self.assertIsNotNone(pulse_modified)
            pulse_modified_dt = datetime.datetime.strptime(pulse_modified, STRP_TIME_FORMAT)
            self.assertGreaterEqual(pulse_modified_dt, three_months_dt)


class TestSearch(TestOTXv2):
    def setUp(self, **kwargs):
        super(TestSearch, self).setUp(**{'api_key': ALIEN_API_APIKEY})

    def test_search_pulses_simple(self):
        pulses, additional_data = self.otx.search_pulses("malware", limit=9)
        self.assertIsNotNone(pulses)
        self.assertTrue(len(pulses) > 0)
        for pulse in pulses:
            print(u"test_search_pulses_simple next pulse: {0}".format(pulse.get('name', '')))
            self.assertIsNotNone(pulse.get('modified', None))
            self.assertIsNotNone(pulse.get('author', None))
            self.assertIsNotNone(pulse.get('id', None))
            self.assertIsNotNone(pulse.get('tags', None))
            self.assertIsNotNone(pulse.get('references', None))
        self.assertTrue(additional_data.get('users_count', -1) >= 0)
        self.assertIsNotNone(additional_data.get('exact_match'))

    def test_exact_match_domain(self):
        pulses, additional_data = self.otx.search_pulses("malware.org", limit=9999)
        self.assertIsNotNone(pulses)
        print("test_exact_match_domain additional data for malware.org:")
        pprint.pprint(additional_data)
        self.assertTrue(additional_data.get('exact_match', -1))


class TestEvents(TestOTXv2):
    def setUp(self, **kwargs):
        super(TestEvents, self).setUp(**{'api_key': ALIEN_API_APIKEY})

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
    def setUp(self, **kwargs):
        super(TestIndicatorTypes, self).setUp(**{'api_key': ALIEN_API_APIKEY})

    def test_get_all_indicators(self):
        indicator_gen = self.otx.get_all_indicators()
        for indicator in indicator_gen:
            self.assertIsNotNone(indicator)
            self.assertIsNotNone(indicator.get('type', None))
            self.assertIsNotNone(indicator.get('indicator', None))
            self.assertIsNotNone(indicator.get('description', None))

    def test_get_all_ipv4_indicators(self):
        ipv4_type_list = [IndicatorTypes.IPv4]
        ipv4_indicator_gen = self.otx.get_all_indicators(indicator_types=ipv4_type_list)
        for indicator in ipv4_indicator_gen:
            self.assertIsNotNone(indicator)
            self.assertIsNotNone(indicator.get('type', None))
            self.assertIsNotNone(indicator.get('indicator', None))
            self.assertIsNotNone(indicator.get('description', None))
            self.assertTrue(indicator.get('type', '') == IndicatorTypes.IPv4.name)


class TestPulseDetails(TestOTXv2):
    def setUp(self, **kwargs):
        super(TestPulseDetails, self).setUp(**{'api_key': ALIEN_API_APIKEY})

    def test_get_pulse_details(self):
        # get a pulse from search to use as testcase
        pulses, additional_data = self.otx.search_pulses("malware", limit=10, page=1)
        pulse = pulses[0]
        pulse_id = pulse.get('id', '')
        meta_data = self.otx.get_pulse_details(pulse_id=pulse_id)
        print("meta data:")
        pprint.pprint(meta_data)
        self.assertIsNotNone(meta_data)
        self.assertTrue('author_name' in meta_data.keys())
        self.assertTrue('name' in meta_data.keys())
        self.assertTrue('references' in meta_data.keys())
        self.assertTrue('tags' in meta_data.keys())
        self.assertTrue('indicators' in meta_data.keys())

    def test_get_pulse_indicators(self):
        pulses, additional_data = self.otx.search_pulses("malware", limit=10, page=1)
        pulse = pulses[0]
        pulse_id = pulse.get('id', '')
        indicators = self.otx.get_pulse_indicators(pulse_id=pulse_id)
        self.assertIsNotNone(indicators)
        self.assertTrue('count' in indicators.keys())
        self.assertTrue('results' in indicators.keys())
        results = indicators.get('results', [])
        for indicator in results:
            print("next indicator:")
            pprint.pprint(indicator)
            self.assertTrue(indicator.get('indicator', '') != '')
            self.assertTrue(indicator.get('type', '') != '')


class TestIndicatorDetails(TestOTXv2):
    def setUp(self, **kwargs):
        super(TestIndicatorDetails, self).setUp(**{'api_key': ALIEN_API_APIKEY})

    def test_get_indicator_details_IPv4_by_section(self):
        print("test_get_indicator_details_IPv4_by_section")
        for section in IndicatorTypes.IPv4.sections:
            print("next section: {0}".format(section))
            section_details = self.otx.get_indicator_details_by_section(IndicatorTypes.IPv4, "69.73.130.198", section)
            print(u"section: {0}".format(section))
            pprint.pprint(section_details)
            self.assertTrue(True)

    def test_get_indicator_details_IPv4_full(self):
        print("test_get_indicator_details_IPv4_full")
        full_details = self.otx.get_full_indicator_details(IndicatorTypes.IPv4, "69.73.130.198")
        print("details: ")
        pprint.pprint(full_details)


class TestPulseCreate(TestOTXv2):
    def setUp(self, **kwargs):
        super(TestPulseCreate, self).setUp(**{'api_key': ALIEN_API_APIKEY})

    def test_create_pulse_simple(self):
        name = "Pyclient-unittests-" + generate_rand_string(8, charset=string.hexdigits).lower()
        print("test_create_pulse_simple submitting pulse: " + name)
        response = self.otx.create_pulse(name=name,
                                         public=False,
                                         indicators=[],
                                         tags=[],
                                         references=[])
        self.assertIsNotNone(response)

    def test_create_pulse_no_name(self):
        print("test_create_pulse_no_name submitting nameless pulse")
        with self.assertRaises(ValueError):
            self.otx.create_pulse(**{})


class TestPulseCreateInvalidKey(TestOTXv2):
    def setUp(self, **kwargs):
        super(TestPulseCreateInvalidKey, self).setUp(**{'api_key': "ALIEN_API_APIKEY"})

    def test_create_pulse_invalid_key(self):
        name = "Pyclient-unittests-" + generate_rand_string(8, charset=string.hexdigits).lower()
        print("test_create_pulse_simple submitting pulse: " + name)
        with self.assertRaises(InvalidAPIKey):
            self.otx.create_pulse(name=name,
                                  public=False,
                                  indicators=[],
                                  tags=[],
                                  references=[])


class TestValidateIndicator(TestOTXv2):
    def setUp(self, **kwargs):
        super(TestValidateIndicator, self).setUp(**{'api_key': ALIEN_API_APIKEY})

    def test_validate_valid_domain(self):
        indicator = generate_rand_string(8, charset=string.ascii_letters).lower() + ".com"
        indicator_type = IndicatorTypes.DOMAIN
        print("test_validate_valid_domain submitting (valid-ish) indicator: " + indicator)
        response = self.otx.validate_indicator(indicator=indicator, indicator_type=indicator_type)
        print ("test_validate_valid_domain response: {}".format(response))
        self.assertIsNotNone(response)
        self.assertTrue('success' in response.get('status', ''))

    def test_validate_invalid_domain(self):
        indicator = generate_rand_string(8, charset=string.ascii_letters).lower()
        indicator_type = IndicatorTypes.DOMAIN
        print("test_validate_invalid_domain submitting indicator: " + indicator)
        response = self.otx.validate_indicator(indicator=indicator, indicator_type=indicator_type)
        print ("test_validate_invalid_domain response: {}".format(response))
        self.assertIsNotNone(response)
        self.assertTrue('failed' in response.get('status', ''))

if __name__ == '__main__':
    unittest.main()
