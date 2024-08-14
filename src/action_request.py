from pydantic import BaseModel


class ActionRequest(BaseModel):
    """ AWS Action request to perform
    """
    Action: str
    Resource: str
    Principal: str = None
    EnvironmentData: dict = {}
    ResourceData: dict = {}
