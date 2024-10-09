from awspolicies.principal import IamRole, AwsService, Resource
from awspolicies.policy import ResourceBasedPolicy, IdentityBasedPolicy
from awspolicies.request_context import RequestContext

ACCOUNT = "123456789012"
REGION = "us-east-1"


# ROLE
role = IamRole(Name="test-role",
               Arn=f"arn:aws:iam::{ACCOUNT}:role/test-role")
role_policy_json = {"Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "s3:AddTafg"
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
                          ]}

# Permisos del rol
role.attach_policy(IdentityBasedPolicy(**role_policy_json))

# Trust policy del permiso
role.attach_policy(ResourceBasedPolicy(**role_trust_policy_json))


# LAMBDA
awslambda = AwsService(Name="test-role",
                            ServiceType="lambda.amazonaws.com",
                            Arn=f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:test-lambda")

# BUCKET
bucket = Resource(Arn="arn:aws:s3:::test-bucket")

with awslambda.assume_role(role):
    r = RequestContext(
        Action="s3:AddTag",
        Resource=bucket,
        Principal=awslambda
    )

    print(r.validate())



