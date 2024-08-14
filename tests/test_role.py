import unittest
from iam_role import IAMRole


class TestIAMRole(unittest.TestCase):

    def test_placeholder(self):
        IAMRole(Name="Fake_role")
        self.assertTrue(True)
