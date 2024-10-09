# Author: santiago93echevarria@gmail.com

from typing import List, Optional
from awspolicies.policy import IdentityBasedPolicy
from awspolicies.resource import Resource
from awspolicies.request_context import RequestContext
from awspolicies.utils.logger import Logger
log = Logger.get_logger(__name__)


class Principal(Resource):
    """ Representation of AWS Principal
    """
    AttachedPolicies: List[IdentityBasedPolicy] = []
    Arn: str
    AssumedRole: str = None

    def permissions_document(self):
        return sum(self.get_policies())

    def assume_role(self, role):
        return AssumedRoleSession(self, role)


class AssumedRoleSession():

    def __init__(self, principal, role):
        r = RequestContext(Principal=principal,
                           Action="sts:AssumeRole",
                           Resource=role)
        r.validate()
        self.old_role = principal.AssumedRole
        self.principal = principal
        self.role = role

    def __enter__(self):
        self.principal.AssumedRole = self.role

    def __exit__(self, exc_type, exc_value, traceback):
        self.principal.AssumedRole = self.old_role


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
    ServiceType: str
    AssumedRole: Optional[IamRole] = None


class FederetedUser(Principal):
    """ Representation of Federeted User
    """
    PrincipalHeader: str = "Federated"


class AwsAccount(Principal):
    """ Representation of AWS Account
    """
    PrincipalHeader: str = "AWS"
