import unittest
from awspolicies.principal import IAMRole


class TestIAMRole(unittest.TestCase):

    def test_placeholder(self):
        IAMRole(Name="Fake_role", Arn="FAkeARN")
        self.assertTrue(True)
