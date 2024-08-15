# Author: santiago93echevarria@gmail.com

import re
from pydantic import BaseModel, model_validator
from typing import List
from awspolicies.policy import Policy
from awspolicies.data.data import REGIONS, RESOURCES


def build_arn(resource):
    """ Return resource ARN
    """
    service_alias = re.findall(r'[A-Z0-9][a-z0-9]*', resource.Type)[0].lower()
    resource_alias = resource.Type.lower().replace(service_alias, "")
    resource_id = resource.Name.lower()
    return f"arn:aws:{service_alias}:{resource.Region}:{resource.Account}:{resource_alias}/{resource_id}"


class Resource(BaseModel, validate_assignment=True):
    Arn: str
    Name: str = None
    Region: str = None
    Account: str = None
    AttachedPolicies: List[Policy] = []

    @model_validator(mode="after")
    def region(self):
        if self.Region is None:
            return self
        elif self.Region not in REGIONS:
            raise ValueError(f"{self.Region} is not a valid region")
        else:
            return self

    def attach_policy(self, policy):
        if not isinstance(policy, Policy):
            raise TypeError(f"{policy} is not of type ResourceBasedPolicy")

        self.AttachedPolicies.append(policy)
