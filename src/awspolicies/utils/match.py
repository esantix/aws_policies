import re
from typing import List, Union
from awspolicies.utils.logger import Logger
log = Logger.get_logger(__name__)


def match(regex: Union[str, None], string: str) -> bool:
    """ Returns True if string matches AWS ARN's RegEx syntax

        RegEx syntax: '*' representes a match for any alphanumeric string, that can include colon or asterisk
        Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html
    """
    log.debug(f"match(regex='{regex}',string='{string}')")
    if regex is None:
        return False
    pattern = re.escape(regex).replace(r"\*", r'[a-zA-Z0-9*:/\-_.]*').replace(r"\?", r'[a-zA-Z0-9]{1}')
    result = bool(re.compile(pattern).fullmatch(string))

    log.debug(f"match(regex='{regex}',string='{string}') => {result}")
    return result


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
