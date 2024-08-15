# Author: santiago93echevarria@gmail.com

from typing import List
from awspolicies.policy import IdentityBasedPolicy
from awspolicies.resource import Resource


class Principal(Resource):
    """ Representation of AWS Principal
    """
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


class IamRole(Principal):
    """ Representation of IAM Role
    """
    PrincipalHeader: str = "AWS"


class IamUser(Principal):
    """ Representation of IAM User
    """
    PrincipalHeader: str = "AWS"


class IamGroup(Principal):
    """ Representation of IAM Group
    """
    PrincipalHeader: str = "AWS"


class AwsService(Principal):
    """ Representation of AWS Service
    """
    PrincipalHeader: str = "Service"


class FederetedUser(Principal):
    """ Representation of Federeted User
    """
    PrincipalHeader: str = "Federated"


class AwsAccount(Principal):
    """ Representation of AWS Account
    """
    PrincipalHeader: str = "AWS"
