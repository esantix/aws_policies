# Author: santiago93echevarria@gmail.com

from typing import List
from pydantic import BaseModel
from role_policy import RolePolicy


class IAMRole(BaseModel):
    """ Representation of AWS Role
    """
    Name: str
    Policies: List[RolePolicy] = []

    def is_allowed(self, action, resource):
        allows = [p.allows(action, resource) for p in self.Policies]
        if False in allows:
            return False
        if True in allows:
            return True

    def attach_policy(self, policy: RolePolicy):
        self.Policies.append(policy)

    def full_policy(self):
        comp = sum(self.Policies)
        comp.Id = f"Role{self.Name}CompositePolicy"
        return comp
