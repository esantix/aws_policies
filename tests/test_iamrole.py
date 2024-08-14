import unittest
from awspolicies.principal import Role


class TestIAMRole(unittest.TestCase):

    def test_placeholder(self):
        Role(Name="Fake_role")
        self.assertTrue(True)
