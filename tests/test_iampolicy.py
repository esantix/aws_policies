#
import shutil
import tempfile
import json
import unittest
from awspolicies.policy import IdentityBasedPolicy


class TestIAMPolicy(unittest.TestCase):

    def setUp(self):
        self.example_policy_dir = 'examples/role_policy.json'
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir)
        pass

    def test_load_save(self):
        save_dir = f'{self.test_dir}/example_saved.json'
        IdentityBasedPolicy.fromfile(self.example_policy_dir).save(save_dir)

        with open(self.example_policy_dir, 'r') as fd1:
            example_json = json.load(fd1)

        with open(save_dir, 'r') as fd2:
            save_json = json.load(fd2)

        self.assertEqual(example_json, save_json)
