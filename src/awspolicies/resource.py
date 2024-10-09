# Author: santiago93echevarria@gmail.com

from pydantic import BaseModel
from typing import List
from awspolicies.policy import Policy


class Resource(BaseModel, validate_assignment=True):
    """ Placeholder for an ARN with attached Policies
    """
    Arn: str
    AttachedPolicies: List[Policy] = []
    AssumedRole: str = None

    def attach_policy(self, policy):
        if not isinstance(policy, Policy):
            raise TypeError(f"{policy} is not of type ResourceBasedPolicy")

        self.AttachedPolicies.append(policy)

    def __repr__(self):
        return self.Arn

    def __str__(self):
        return self.__repr__()

    def get_policies(self):
        if self.AssumedRole:
            return self.AssumedRole.AttachedPolicies
        else:
            return self.AttachedPolicies
