from awspolicies.utils.logger import Logger
log = Logger.get_logger(__name__)

class Constructor():

    def fromtable():
        """
        Expected DataFrame:
            | Action          | Resource  | Allow   | [Deny]  | C
            ---------------------------------------------------
            | s3:CreateBucket |  <regex>  | <regex> | <regex> |

        """
