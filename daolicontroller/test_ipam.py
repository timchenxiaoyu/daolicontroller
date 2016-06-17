import unittest

from ipam import IPAM

class TestIPAM(unittest.TestCase):

    def setUp(self):
        self.ipam = IPAM()

    def test_alloc(self):
        self.assertEqual(self.ipam.alloc(), '10.0.0.1')
        self.assertEqual(self.ipam.alloc(), '10.0.0.2')

    def test_deloc(self):
        self.ipam.deloc('10.0.0.3')
        self.assertEqual(self.ipam.alloc(), '10.0.0.3')

if __name__ == '__main__':
    unittest.main()
