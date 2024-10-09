import unittest
from awspolicies.principal import IamRole, AwsService, Resource
from awspolicies.policy import ResourceBasedPolicy, IdentityBasedPolicy
from awspolicies.request_context import RequestContext

ACCOUNT = "123456789012"
REGION = "us-east-1"


class TestActions(unittest.TestCase):

    def setUp(self):
        self.role = IamRole(Name="test-role",
                            Arn=f"arn:aws:iam::{ACCOUNT}:role/test-role")

        self.awslambda = AwsService(Name="test-role",
                                    ServiceType="lambda",
                                    Arn=f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:test-lambda")

        self.bucket = Resource(Arn="arn:aws:s3:::test-bucket")

    def test_action1(self):

        role_policy_json = {"Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                        "s3:AddTag"
                                    ],
                                    "Resource": "*"
                                }
                            ]}
        role_trust_policy_json = {"Version": "2012-10-17",
                                  "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Principal": {
                                                "Service": "lambda.amazonaws.com"
                                            },
                                            "Action": "sts:AssumeRole"
                                        }
                                    ]
                                }
        

        self.role.attach_policy(IdentityBasedPolicy(**role_policy_json))
        self.role.attach_policy(ResourceBasedPolicy(**role_trust_policy_json))


        self.awslambda.assume_role(self.role)

