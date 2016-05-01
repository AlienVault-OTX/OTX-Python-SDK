import unittest
from OTXv2 import OTXv2


class TestOTXv2(unittest.TestCase):
    def setUp(self):
        self.api_key = "48db25670b590ae34850cb13e25397e1e6cad56f2c4f7bdae75a1121dc76bdd0"
        self.otx = OTXv2(self.api_key)


class TestSubscriptions(TestOTXv2):
    def setUp(self):
        super(TestSubscriptions, self).setUp()

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
        self.assertIsNotNone(most_recent.get('id', None))


if __name__ == '__main__':
    unittest.main()
