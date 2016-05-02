import unittest
import datetime
import dateutil.parser

from utils import generate_rand_string
from OTXv2 import OTXv2, InvalidAPIKey
from IndicatorTypes import IPv4

ALIEN_API_APIKEY = "48db25670b590ae34850cb13e25397e1e6cad56f2c4f7bdae75a1121dc76bdd0"


class TestOTXv2(unittest.TestCase):
    def setUp(self, **kwargs):
        provided_key = kwargs.get('api_key', '')
        if provided_key:
            self.api_key = provided_key
        else:
            self.api_key = ALIEN_API_APIKEY
        self.otx = OTXv2(self.api_key)


class TestSubscriptionsInvalidKey(TestOTXv2):
    def setUp(self, **kwargs):
        super(TestSubscriptionsInvalidKey, self).setUp(**{'api_key': generate_rand_string(length=64)})

    def test_getall(self):
        with self.assertRaises(InvalidAPIKey):
            self.otx.getall()


class TestSubscriptions(TestOTXv2):
    def setUp(self, **kwargs):
        super(TestSubscriptions, self).setUp(**{'api_key': ALIEN_API_APIKEY})

    def test_getall(self):
        pulses = self.otx.getall()
        self.assertIsNotNone(pulses)
        self.assertTrue(len(pulses) > 0)
        most_recent = pulses[0]
        print "most recent pulse: {0}".format(most_recent.get('name', ''))
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
            self.assertTrue(pulse.get('name', None))

    def test_getsince(self):
        three_months_dt = (datetime.datetime.now() - datetime.timedelta(days=90))
        three_months_timestamp = three_months_dt.isoformat()
        pulses = self.otx.getsince(three_months_timestamp, limit=9999)
        for pulse in pulses:
            pulse_modified = pulse.get('modified', None)
            self.assertIsNotNone(pulse_modified)
            pulse_modified_dt = dateutil.parser.parse(pulse_modified)
            self.assertGreaterEqual(pulse_modified_dt, three_months_dt)

    def test_getsince_iter(self):
        three_months_dt = (datetime.datetime.now() - datetime.timedelta(days=90))
        three_months_timestamp = three_months_dt.isoformat()
        pulse_gen = self.otx.getsince_iter(three_months_timestamp, limit=9999)
        self.assertIsNotNone(pulse_gen)
        for pulse in pulse_gen:
            self.assertTrue(pulse.get('name', None))
            pulse_modified = pulse.get('modified', None)
            self.assertIsNotNone(pulse_modified)
            pulse_modified_dt = dateutil.parser.parse(pulse_modified)
            self.assertGreaterEqual(pulse_modified_dt, three_months_dt)


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
        print "Next event: {0}".format(most_recent.keys())
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
        ipv4_type_list = [IPv4]
        ipv4_indicator_gen = self.otx.get_all_indicators(indicator_types=ipv4_type_list)
        for indicator in ipv4_indicator_gen:
            self.assertIsNotNone(indicator)
            self.assertIsNotNone(indicator.get('type', None))
            self.assertIsNotNone(indicator.get('indicator', None))
            self.assertIsNotNone(indicator.get('description', None))
            self.assertTrue(indicator.get('type', '') == IPv4.name)

if __name__ == '__main__':
    unittest.main()
