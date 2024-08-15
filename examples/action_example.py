from awspolicies.principal import Role
from awspolicies.policy import IdentityBasedPolicy, ResourceBasedPolicy
from awspolicies.action_request import ActionRequest
from awspolicies.aws_resource import *


ACCOUNT = "123456789012"
REGION = "us-east-1"
ROLE_NAME = "BucketTagger"


# Role with policy
role = Role(Arn=f"arn:aws:iam::{ACCOUNT}:role/{ROLE_NAME}")
role_policy = IdentityBasedPolicy.fromfile("examples/role_policy.json")
role.attach_policy(role_policy)

# Resource with policy
bucket = S3Bucket(Name="MyBucket",
                  Region=REGION,
                  Account=ACCOUNT)
bucket_policy = ResourceBasedPolicy.fromfile("examples/bucket_policy.json")
bucket.attach_policy(bucket_policy)

# Action request
action_request = ActionRequest(Action="AddTag",
                               Resource=bucket,
                               Principal=role)

print(f"Action is allowed? {action_request.is_allowed()}")
