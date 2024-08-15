# Author: santiago93echevarria@gmail.com

from pydantic import BaseModel
from awspolicies.aws_resource import AWSResource
from awspolicies.principal import Principal
from awspolicies.utils.logger import LoggerConfig
log = LoggerConfig.get_logger(__name__)


class ActionRequest(BaseModel):
    """ AWS Action request to perform
    """
    Action: str
    Resource: AWSResource
    Principal: Principal
    EnvironmentData: dict = {}
    ResourceData: dict = {}

    def is_allowed(self):

        log.debug(f'resource type: {self.Resource.Type}')
        log.debug(f'resource arn: {self.Resource.Arn}')
        log.debug(f'principal type: {self.Principal.__class__.__name__}')
        log.debug(f'principal arn: {self.Principal.Arn}')

        log.info("Checking Resource policies...")
        resource_allows = False
        for rb_policies in self.Resource.AttachedPolicies:
            pass

        log.info("Checking Principal policies...")
        principal_is_allowed = False
        for ib_policies in self.Principal.AttachedPolicies:
            pass

        return resource_allows and principal_is_allowed
