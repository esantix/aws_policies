import unittest
from awspolicies.principal import IamRole


class TestIAMRole(unittest.TestCase):

    def test_placeholder(self):
        IamRole(Name="Fake_role", Arn="FAkeARN")
        self.assertTrue(True)
