import unittest
from config import *

class TestConfig(unittest.TestCase):
    def test_global_var(self):
        value = 5
        self.assertEqual(GLOBAL_VARS['MAX_HOPS_WITHOUT_END_NODE'], value)