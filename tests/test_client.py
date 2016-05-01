import unittest
import datetime
import dateutil.parser

from utils import generate_rand_string
from OTXv2 import OTXv2, InvalidAPIKey

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
        year_ago_dt = (datetime.datetime.now() - datetime.timedelta(days=90))
        year_ago_timestamp = year_ago_dt.isoformat()
        pulses = self.otx.getsince(year_ago_timestamp, limit=9999)
        for pulse in pulses:
            pulse_modified = pulse.get('modified', None)
            self.assertIsNotNone(pulse_modified)
            pulse_modified_dt = dateutil.parser.parse(pulse_modified)
            self.assertGreaterEqual(pulse_modified_dt, year_ago_dt)


if __name__ == '__main__':
    unittest.main()
