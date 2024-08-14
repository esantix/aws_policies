# Author: santiago93echevarria@gmail.com

import json
import re
from pydantic import BaseModel, model_validator, ValidationError
from typing import Optional, Literal, List, Union


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
    Condition: dict = None

    @model_validator(mode="after")
    def uniqueness(self):
        if not (self.Action is None) != (self.NotAction is None):
            raise ValidationError()
        if self.Principal is not None and self.NotPrincipal is not None:
            raise ValidationError()
        if not (self.Resource is None) != (self.NotResource is None):
            raise ValidationError()
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


class RolePolicy(BaseModel, validate_assignment=True):
    """ Representation of AWS IAM Policy

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html
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

    def allows(self, action, resource):
        """ Whether policy allows an action/resource

            Returns:
                True: policy explicitly allows it
                False: policy explicitly denies it
                None: policy does not state effect on it
        """
        effects = []
        for statement in self.Statement:
            effects.append(statement.effect(action, resource))

        if "Deny" in effects:
            return False
        if "Allow" in effects:
            return True
        else:
            return None

    def __add__(self, new):
        if self.Version != new.Version:
            raise ValueError("Policies have different Version")

        statements = self.Statement + new.Statement
        return RolePolicy(Version=self.Version, Statement=statements)

    def __iadd__(self, new):
        if self.Version != new.Version:
            raise ValueError("Policies have different Version")

        self.Statement += new.Statement
        return self

    def __radd__(self, new):
        if new == 0:
            return self
        else:
            return self + new

    @classmethod
    def fromfile(cls, path):
        with open(path, "r") as fd:
            data = json.load(fd)

        return RolePolicy(**data)


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
