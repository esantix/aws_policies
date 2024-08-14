from pydantic import BaseModel
from aws_resource import AWSResource
from iam.principal import Principal


class ActionRequest(BaseModel):
    """ AWS Action request to perform
    """
    Action: str
    Resource: AWSResource
    Principal: Principal
    EnvironmentData: dict = {}
    ResourceData: dict = {}

    def is_allowed(self):

        print("Checking Resource policies...")
        resource_allows = False
        for rb_policies in self.Resource.AttachedPolicies:
            pass

        print("Checking Principal policies...")
        principal_is_allowed = False
        for ib_policies in self.Principal.AttachedPolicies:
            pass

        return resource_allows and principal_is_allowed
