import pandas as pd
from awspolicies.policy import Statement, IdentityBasedPolicy
import re
import os
import json

def load_config(path):
    with open(path, "r") as f:
        config = json.load(f)
    return config


def load_excel(path):
    """ Loads an Excel file into a pandas DataFrame.
    """
    df = pd.read_excel(path)
    return df

def get_prefix(string):
    """"""
    res_list = re.findall('[A-Z][^A-Z]*', string)
    try:
        if len(res_list[0]) > 1:
            return res_list[0]
        else:
            return string
    except IndexError:
        return None



def make_inline_policy(df, service_group, add_deny=False, config={}):
    """ Processes a pandas DataFrame.
    """
    # Process the DataFrame (df) as needed
    role_name = df.columns[2]

    statements = []

    for service in service_group:
        srv_df = df[df["Service Alias"] == service]
        service_actions_count = srv_df.shape[0]

        allowed_srv_df = srv_df[srv_df[role_name] != "Deny"]

        resource_regexes = allowed_srv_df[role_name].unique().tolist()

        for resource_regex in resource_regexes:

            same_resource_df = allowed_srv_df[(allowed_srv_df[role_name] == resource_regex)]

            if same_resource_df.shape[0] == service_actions_count != 0:
                action_regex = f'{service}:*'

                resource_regex = resource_regex.replace(" ", "").replace("\n", "").split(";")
                resource_regex = resource_regex[0] if len(resource_regex) == 1 else resource_regex

                statements.append(Statement(
                    Effect="Allow",
                    Action=action_regex,
                    Resource="asda"
                ))
            else:

                action_regex = []
                for prefix in same_resource_df["Prefix"].unique().tolist():
                    if f'{service}:{prefix}' not in config["PrefixGroupingExcluded"]:

                        df2 = allowed_srv_df[(allowed_srv_df["Prefix"] == prefix) & (allowed_srv_df[role_name] == resource_regex)]
                        action_regex += [f'{service}:{action}' for action in df2["Action"].tolist()]
                    else:
                        prefix_group_regex = srv_df[srv_df["Prefix"] == prefix]
                        prefix_group = allowed_srv_df[(allowed_srv_df["Prefix"] == prefix) & (allowed_srv_df[role_name] == resource_regex)]

                        if prefix_group.shape[0] == prefix_group_regex.shape[0] != 0:
                            action_regex.append(f'{service}:{prefix}*')
                        else:
                            df2 = allowed_srv_df[(allowed_srv_df["Prefix"] == prefix) & (allowed_srv_df[role_name] == resource_regex)]
                            action_regex += [f'{service}:{action}' for action in df2["Action"].tolist()]



                action_regex = action_regex[0] if len(action_regex) == 1 else action_regex
                resource_regex = resource_regex.replace(" ", "").replace("\n", "").split(";")
                resource_regex = resource_regex[0] if len(resource_regex) == 1 else resource_regex
                statements.append(Statement(Effect="Allow", Action=action_regex, Resource=resource_regex))
        
        if add_deny:

            deny_df = srv_df[srv_df[role_name] == "Deny"]
            if deny_df.shape[0] != 0:
                if deny_df.shape[0] == service_actions_count:
                    d_action_regex = f'{service}:*'
                else:
                    d_action_regex = [f'{service}:{action}' for action in deny_df["Action"].unique().tolist()]
                    statements.append(Statement(
                        Effect="Deny",
                        Action=d_action_regex,
                        Resource="*"
                    ))
    return IdentityBasedPolicy(Id=role_name, Statement=statements, Version="2012-10-17")



def build_all_policies(fd: tuple, add_deny: bool = False, out_dir: str = "./data"):

    in_group_services = []
    service_groups = CONFIG["ServiceGroups"]


    for service_group in service_groups:
        in_group_services += service_groups[service_group]

        if not os.path.exists(out_dir):
            os.makedirs(out_dir)

    if isinstance(fd, str):
        df = pd.read_excel(fd)
    else:
        df = pd.read_excel(fd[0], sheet_name=fd[1])

    services = df["Service Alias"].unique().tolist()
    
    if CONFIG["IncludeNoGroup"]:
        others = [service for service in services if service not in in_group_services]
        if others:
            if "Extras" in service_groups.keys():
                raise ValueError("Extras key already exists in the service group dictionary.")
            else:
                service_groups["Extras"] = others

    df["Prefix"] = df["Action"].apply(get_prefix)     


    for role_column in df.columns[2:-1]:
        try:
            os.mkdir(f"{out_dir}/{role_column}")
        except FileExistsError:
            pass

        for service_group_name ,service_group in service_groups.items():

            policy = make_inline_policy(df[["Service Alias", "Action", role_column, "Prefix"]], service_group, add_deny, config=CONFIG)
            
            if len(policy.Statement) != 0:
                policy.save(f"{out_dir}/{role_column}/{role_column}_{service_group_name}.json")  


CONFIG = load_config("/Users/santiagoechevarria/Documents/code/aws_policies/src/builder/config.json")


def main():
    path = "/Users/santiagoechevarria/Documents/code/aws_policies/data/template.xlsx"
    build_all_policies(path, add_deny=False, out_dir="/Users/santiagoechevarria/Documents/code/aws_policies/data/roles")

main()

