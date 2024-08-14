# Author: santiago93echevarria@gmail.com

import re
from pydantic import BaseModel, model_validator
from typing import List
from iam.policy import ResourceBasedPolicy

REGIONS = ["us-east-1", "us-east-2",
           "us-west-1", "us-west-2",
           "ca-central-1",
           "sa-east-1",
           "eu-west-1", "eu-west-2", "eu-west-3",
           "eu-central-1",
           "eu-north-1",
           "eu-south-1", "eu-south-2",
           "me-south-1", "me-central-1",
           "il-central-1",
           "af-south-1",
           "ap-south-1", "ap-south-2", "ap-east-1",
           "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
           "ap-southeast-1", "ap-southeast-2", "ap-southeast-3",
           "cn-north-1", "cn-northwest-1", "us-gov-east-1", "us-gov-west-1"]


class AWSResource(BaseModel, validate_assignment=True):
    ServiceFamiliy: str
    Arn: str
    Region: str
    Account: str
    AttachedPolicies: List[ResourceBasedPolicy] = []

    @model_validator(mode="after")
    def arn(self):
        arn_regex = r"^arn:(aws|aws-cn|aws-us-gov|aws-iso|aws-iso-b):[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]*:\d{12}:[a-zA-Z0-9_/.-]+$"
        if not re.match(arn_regex, self.Arn):
            raise ValueError(f"{self.Arn} is not a valid ARN")
        return self

    @model_validator(mode="after")
    def region(self):
        if self.Region not in REGIONS:
            raise ValueError(f"{self.Region} is not a valid region")
        return self

    def attach_policy(self, policy):
        if not isinstance(policy, ResourceBasedPolicy):
            raise TypeError(f"{policy} is not of type ResourceBasedPolicy")

        self.AttachedPolicies.append(policy)
