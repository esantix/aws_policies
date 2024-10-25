# Author: santiago93echevarria@gmail.com

import requests
import pandas as pd

def get_aws_iam_actions():
    """ Gets a mapping of all available AWS IAM actions.
    Returns:
        dict: A dictionary where the keys are the service alias and the values are lists of actions.
    """

    url = "https://www.awsiamactions.io/json"
    response = requests.get(url)
    response.raise_for_status()  # Raise an exception for HTTP errors

    mapping = {}
    for service in response.json():
        mapping[service["servicePrefix"]] = []  
        for action in service["actions"]:
            mapping[service["servicePrefix"]].append(action["action"].split(":")[-1])   
        
    return mapping

def build_dataframe():
    """ Builds a pandas DataFrame with the available AWS IAM actions.
    """
    actions = get_aws_iam_actions()
    rows = []
    for service, actions_list in actions.items():
        for action in actions_list:
            rows.append({"Service Alias": service, "Action": action})
    
    df = pd.DataFrame(rows, columns=["Service Alias", "Action"])
    
    return df


def make_template(file_path):
    """ Creates a template for the IAM policy.
    """
    df = build_dataframe()
    df["<Insert role name>"] = "Deny"
    df.to_excel(file_path, index=False)
