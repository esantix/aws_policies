# Author: santiago93echevarria@gmail.com

from pydantic import BaseModel, model_validator
from typing import Any
from awspolicies.resource import Resource
from awspolicies.principal import Principal
from awspolicies.utils.logger import LoggerConfig
log = LoggerConfig.get_logger(__name__)


class ActionRequest(BaseModel):
    """ AWS Action request to perform
    """
    Action: str
    Resource: Resource
    Principal: Any
    EnvironmentData: dict = {}
    ResourceData: dict = {}

    @model_validator(mode="after")
    def principal(self):
        if not isinstance(self.Principal, Principal):
            raise ValueError(f"{self.Principal.Type} is not of type Principal")
        return self

    def is_allowed(self):
        """ Define if action is allowed
        """
        log.info(f'resource arn: {self.Resource.Arn}')
        log.info(f'principal arn: {self.Principal.Arn}')

        resource_allows = []
        for rb_policy in self.Resource.AttachedPolicies:
            rb_allow = rb_policy.evaluate(self)
            resource_allows.append(rb_allow)
            log.info(rb_allow)
        log.info(f'Resources side allows: {resource_allows}')

        principal_allows = []
        for ib_policy in self.Principal.AttachedPolicies:
            ib_allow = ib_policy.evaluate(self)
            principal_allows.append(ib_allow)
            log.info(ib_allow)
        log.info(f'Principal side allows: {principal_allows}')

        all_allows = principal_allows + resource_allows

        if "Deny" in all_allows:
            return False
        elif "Allow" in all_allows:
            return True
        else:
            return None
