# Author: santiago93echevarria@gmail.com

"""

#################################################################################
#                                 IMPORTANT                                     #
#################################################################################

    Action requests in this library do not consider IAM Permission Boundaries nor
    AWS Organizations service control policies (SCPs). Use wisely.

"""

from pydantic import BaseModel
from typing import Any
from awspolicies.utils.logger import Logger
from awspolicies.effect import Allow, Deny

import sys

log = Logger.get_logger(__name__)


class PermissionDeniedException(Exception):
    """Custom exception to indicate permission denial."""


class RequestContext(BaseModel):
    """ AWS Action request to perform
    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
    """
    Action: Any
    Resource: Any
    Principal: Any
    EnvironmentData: dict = {}
    ResourceData: dict = {}

    def __is_allowed(self):
        """ Define if action is allowed
        """
        log.info(f'ActionRequest.Principal.Arn == {self.Principal.Arn}')
        log.info(f'ActionRequest.Action == {self.Action}')
        log.info(f'ActionRequest.Resource.Arn == {self.Resource.Arn}')

        resource_policies_effects = []
        for rb_policy in self.Resource.get_policies():
            rb_effect = rb_policy.effect(self)
            resource_policies_effects.append(rb_effect)

        log.info(f'ActionRequest.Resource allows == {resource_policies_effects}')

        principal_policies_effects = []
        for ib_policy in self.Principal.get_policies():
            ib_effects = ib_policy.effect(self)
            principal_policies_effects.append(ib_effects)

        log.info(f'ActionRequest.Principal allows == {principal_policies_effects}')

        all_effects = principal_policies_effects + resource_policies_effects

        if Deny in all_effects:
            result = False
        elif Allow in all_effects:
            result = True
        else:
            result = False

        log.info(f'ActionRequest == {result}')
        return result

    def validate(self):
        """ Validate if action is allowed
        """
        if self.__is_allowed():
            return True
        else:
            sys.tracebacklimit = -1
            raise PermissionDeniedException(f"\n\033[91mAccessDenied: \033[1m{self.Principal}\033[0m\033[91m is not authorized to perform: \033[1m{self.Action}\033[0m\033[91m on resource: \033[1m{self.Resource}\033[0m")
