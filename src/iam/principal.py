# Author: santiago93echevarria@gmail.com

from typing import List
from pydantic import BaseModel
from iam.policy import IdentityBasedPolicy


class Principal(BaseModel):
    """ Representation of AWS Principal
    """
    Arn: str
    AttachedPolicies: List[IdentityBasedPolicy] = []

    def is_allowed(self, action, resource):
        allows = [p.evaluate(action, resource) for p in self.AttachedPolicies]
        if False in allows:
            return False
        if True in allows:
            return True

    def attach_policy(self, policy) -> IdentityBasedPolicy:
        if not isinstance(policy, IdentityBasedPolicy):
            raise TypeError(f"{policy} is not of type IdentityBasedPolicy")

        self.AttachedPolicies.append(policy)

    def full_policy(self):
        comp = sum(self.AttachedPolicies)
        comp.Id = f"Principal{self.Name}CompositePolicy"
        return comp


class Role(Principal):
    """ Representation of AWS Role
    """
