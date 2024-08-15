from awspolicies.principal import IamRole
from awspolicies.policy import IdentityBasedPolicy, ResourceBasedPolicy
from awspolicies.action_request import ActionRequest
from awspolicies.resource import Resource

ACCOUNT = "123456789012"
REGION = "us-east-1"


# Role with policy
role = IamRole(Arn=f"arn:aws:iam::{ACCOUNT}:role/santiago",
               Account=ACCOUNT,
               Region=REGION
               )
role_policy = IdentityBasedPolicy.fromfile("examples/role_policy.json")
role.attach_policy(role_policy)

# Resource with policy
bucket = Resource(Arn="arn:aws:s3:::mybucket")
bucket_policy = ResourceBasedPolicy.fromfile("examples/bucket_policy.json")
bucket.attach_policy(bucket_policy)

# Action request
action_request = ActionRequest(Action="s3:AddTag",
                               Resource=bucket,
                               Principal=role)

print(f"Action is allowed? {action_request.is_allowed()}")
