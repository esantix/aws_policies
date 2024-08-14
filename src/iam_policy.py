# Author: santiago93echevarria@gmail.com

import json
import re
from pydantic import BaseModel, model_validator, ValidationError
from typing import Optional, Literal, List, Union
from action_request import ActionRequest


def match(regex: Union[str, None], string: str) -> bool:
    """ Returns True if string matches AWS ARN's RegEx syntax

        RegEx syntax: '*' representes a match for any alphanumeric string, that can include colon or asterisk
        Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html
    """
    if regex is None:
        return False
    pattern = re.escape(regex).replace(r"\*", r'[a-zA-Z0-9*:]*').replace(r"\?", r'[a-zA-Z0-9]{1}')
    return bool(re.compile(pattern).fullmatch(string))


def matches_any(regex: Union[str, List[str], None], string) -> bool:
    """ Returns True if string matches any AWS ARN's RegEx syntax
    """
    matches = False
    if isinstance(regex, list):
        for r in regex:
            matches = matches or match(r, string)
    else:
        matches = match(regex, string)
    return matches


class ConditionBlock(BaseModel):
    """ Condition Block
        Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
    """
    StringEquals: dict = None
    StringEqualsIfExists: dict = None
    StringNotEquals: dict = None
    StringNotEqualsIfExists: dict = None
    StringEqualsIgnoreCase: dict = None
    StringEqualsIgnoreCaseIfExists: dict = None
    StringNotEqualsIgnoreCase: dict = None
    StringNotEqualsIgnoreCaseIfExists: dict = None
    StringLike: dict = None
    StringLikeIfExists: dict = None
    StringNotLike: dict = None
    StringNotLikeIfExists: dict = None
    NumericEquals: dict = None
    NumericEqualsIfExists: dict = None
    NumericNotEquals: dict = None
    NumericNotEqualsIfExists: dict = None
    NumericLessThan: dict = None
    NumericLessThanIfExists: dict = None
    NumericLessThanEquals: dict = None
    NumericLessThanEqualsIfExists: dict = None
    NumericGreaterThan: dict = None
    NumericGreaterThanIfExists: dict = None
    NumericGreaterThanEquals: dict = None
    NumericGreaterThanEqualsIfExists: dict = None
    DateEquals: dict = None
    DateEqualsIfExists: dict = None
    DateNotEquals: dict = None
    DateNotEqualsIfExists: dict = None
    DateLessThan: dict = None
    DateLessThanIfExists: dict = None
    DateLessThanEquals: dict = None
    DateLessThanEqualsIfExists: dict = None
    DateGreaterThan: dict = None
    DateGreaterThanIfExists: dict = None
    DateGreaterThanEquals: dict = None
    DateGreaterThanEqualsIfExists: dict = None
    Bool: dict = None
    BoolIfExists: dict = None
    BinaryEquals: dict = None
    BinaryEqualsIfExists: dict = None
    IpAddress: dict = None
    IpAddressIfExists: dict = None
    NotIpAddress: dict = None
    NotIpAddressIfExists: dict = None
    ArnEquals: dict = None
    ArnEqualsIfExists: dict = None
    ArnNotEquals: dict = None
    ArnNotEqualsIfExists: dict = None
    ArnLike: dict = None
    ArnLikeIfExists: dict = None
    ArnNotLike: dict = None
    ArnNotLikeIfExists: dict = None
    Null: dict = None

    @model_validator(mode="after")
    def uniqueness(self):
        if len(self.model_fields_set) != 1:
            raise ValueError("One and only one field must be set")
        return self


class PrincipalBlock(BaseModel, validate_assignment=True):
    """ Representation of AWS IAM Policy Statement Principal Block
    """

    AWS: List[str] = None
    Federated: List[str] = None
    Service: List[str] = None
    CanonicalUser: List[str] = None


class Statement(BaseModel, validate_assignment=True):
    """ Representation of AWS IAM Policy Statement
    """
    Sid: str = None
    Principal: Union[Literal["*"], PrincipalBlock] = None
    NotPrincipal: Union[Literal["*"], PrincipalBlock] = None
    Effect: Literal["Allow", "Deny"]
    Action: Union[str, List[str]] = None
    NotAction: Union[str, List[str]] = None
    Resource: Union[str, List[str]] = None
    NotResource: Union[str, List[str]] = None
    Condition: Union[ConditionBlock, List[ConditionBlock]] = None

    @model_validator(mode="after")
    def uniqueness(self):
        if not (self.Action is None) != (self.NotAction is None):
            raise ValidationError("Action OR NotAction must be defined")
        if self.Principal is not None and self.NotPrincipal is not None:
            raise ValidationError("Principal OR NotPrincipal must be defined")
        if not (self.Resource is None) != (self.NotResource is None):
            raise ValidationError("Resource OR NotResource must be defined")
        return self

    def _reaches(self, action, resource):
        """ Returns True if action/resource pair is reached by statement
        """
        return matches_any(self.Action, action) and matches_any(self.Resource, resource)

    def effect(self, action, resource):
        """ Effect of statement on action/resource expression

            Returns:
                "Allow": Action/Resource is Allowed by statement
                "Deny": Action/Resource is Denied by statement
                None: Action/Resource is not reached by statement
        """
        if self._reaches(action, resource):
            return self.Effect
        else:
            return None


class IAMPolicy(BaseModel, validate_assignment=True):
    """ Representation of AWS IAM Policy

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies.html
    """
    Version: Literal["2008-10-17", "2012-10-17"] = None
    Id: Optional[str] = None
    Statement: List[Statement]

    @model_validator(mode="after")
    def length(self):
        MAX_LENGTH = 10240
        json_length = len(json.dumps(self.model_dump(exclude_unset=True)).replace(" ", ""))
        if json_length > MAX_LENGTH:
            raise ValueError(f"Policy JSON exceeds {MAX_LENGTH}. (#Chars={json_length}, #Statements={len(self.Statement)})")
        return self

    def save(self, path):
        with open(path, "w") as fd:
            json.dump(self.model_dump(exclude_unset=True), fd, indent=3)

    def __evaluate(self, action_request: ActionRequest) -> bool:
        """ Whether policy allows an action/resource

            Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html

            Returns:
                True: policy explicitly allows it
                False: policy explicitly denies it
                None: policy does not state effect on it
        """
        effects = []
        for statement in self.Statement:
            effects.append(statement.effect(action_request.Action, action_request.Resource))

        if "Deny" in effects:
            return False
        if "Allow" in effects:
            return True
        else:
            return None

    def evaluate(self, action_request: ActionRequest):
        return self.__evaluate(action_request)

    def __add__(self, new):
        if self.Version != new.Version:
            raise ValueError("Policies have different Version")

        statements = self.Statement + new.Statement
        return IAMPolicy(Version=self.Version, Statement=statements)

    def __iadd__(self, new):
        return self + new.Statement

    def __radd__(self, new):
        if new == 0:
            return self
        else:
            return self + new

    @classmethod
    def fromfile(cls, path):
        try:
            with open(path, "r") as fd:
                data = json.load(fd)
            return cls(**data)
        
        except (ValueError, ValidationError):
            raise ValueError(f"{path} is not a valid {cls.__name__}")


class IdentityBasedPolicy(IAMPolicy):
    """ Identity-based policies are attached to an IAM identity (user, group of users, or role)
        and grant permissions to IAM entities (users and roles).
    """


class ResourceBasedPolicy(IAMPolicy, validate_assignment=True):
    """ Resource-based policies grant permissions to the principal (account, user, role, and
        session principals such as role sessions and IAM federated users ) specified as the principal.
    """

    @model_validator(mode="after")
    def principal(self):
        print(self)
        for statement in self.Statement:
            print(statement)
            if statement.Principal is None:
                raise ValueError("ResourceBasedPolicies staements must have a defined Principal")
        return self


# class IAMPermissionsBoundary(IAMPolicy):
#     """ Permissions boundaries are an advanced feature that sets the maximum permissions that an
#         identity-based policy can grant to an IAM entity (user or role).
#     """


# class ServiceControlPolicy(IAMPolicy):
#     """ Organizations SCPs specify the maximum permissions for an organization or organizational unit (OU).
#     """


# class SessionPolicy(IAMPolicy):
#     """ Session policies are advanced policies that you pass as parameters when you programmatically
#     create a temporary session for a role or federated user. To create a role session programmatically,
#     use one of the AssumeRole* API operations.
#     """
