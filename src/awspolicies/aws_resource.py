# Author: santiago93echevarria@gmail.com

import re
from pydantic import BaseModel, model_validator
from typing import List
from awspolicies.policy import ResourceBasedPolicy
from awspolicies.data.data import REGIONS, RESOURCES


class AWSResource(BaseModel, validate_assignment=True):
    Arn: str = None
    Type: str = None
    Name: str
    Region: str
    Account: str
    AttachedPolicies: List[ResourceBasedPolicy] = []

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # TODO: check if this ARN build is actually true
        self.Type = self.__class__.__name__
        service_alias = re.findall(r'[A-Z0-9][a-z0-9]*', self.Type)[0].lower()
        resource_alias = self.Type.lower().replace(service_alias, "")
        resource_id = self.Name.lower()
        self.Arn = f"arn:aws:{service_alias}:{self.Region}:{self.Account}:{resource_alias}/{resource_id}"

    @model_validator(mode="after")
    def region(self):
        if self.Region not in REGIONS:
            raise ValueError(f"{self.Region} is not a valid region")
        return self
    
    def attach_policy(self, policy):
        if not isinstance(policy, ResourceBasedPolicy):
            raise TypeError(f"{policy} is not of type ResourceBasedPolicy")

        self.AttachedPolicies.append(policy)


for res in RESOURCES:
    globals()[res] = type(res, (AWSResource,), {})

