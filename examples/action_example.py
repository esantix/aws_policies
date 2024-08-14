from iam.principal import Role
from iam.policy import IdentityBasedPolicy, ResourceBasedPolicy
from action_request import ActionRequest
from aws_resource import AWSResource

ACCOUNT = "123456789012"
REGION = "us-east-1"
ROLE_NAME = "BucketTagger"

# Role with policy
role = Role(Arn=f"arn:aws:iam::{ACCOUNT}:role/{ROLE_NAME}")
role_policy = IdentityBasedPolicy.fromfile("examples/role_policy.json")
role.attach_policy(role_policy)

# Resource with policy
bucket = AWSResource(ServiceFamiliy="s3",
                     Arn=f"arn:aws:s3:{REGION}:{ACCOUNT}:bucket/mybucket",
                     Region=REGION,
                     Account=ACCOUNT)
bucket_policy = ResourceBasedPolicy.fromfile("examples/bucket_policy.json")
bucket.attach_policy(bucket_policy)

# Action request
action_request = ActionRequest(Action="AddTag",
                               Resource=bucket,
                               Principal=role)

print(f"Action is allowed? {action_request.is_allowed()}")
