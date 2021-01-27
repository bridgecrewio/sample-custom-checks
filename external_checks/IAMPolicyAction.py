import json

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

# substrings that must not be in the policy
disallowed_actions = [
    's3:*',
    's3:Get',
    's3:List'
]

class IAMPolicyShouldNotUseAction(BaseResourceCheck):
    def __init__(self):
        name = "IAM policy should not grant S3 permissions"
        id = "CKV_ORG_CUSTOM_002"
        supported_resources = ['aws_iam_policy']
        categories = [CheckCategories.IAM]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'policy' not in conf:
            return CheckResult.UNKNOWN

        policy = conf['policy']
        if type(policy) == list:
            policy = policy[0]

        policy_obj = json.loads(policy)
        statements = policy_obj['Statement']
        for statement in statements:
            actions = statement['Action']
            if type(actions) == str:
                actions = [actions]
            for action in actions:
                for disallowed_action in disallowed_actions:
                    if disallowed_action in action:
                        return CheckResult.FAILED

        return CheckResult.PASSED

    def get_tag_value(self, tag_name, tags):
        for tag in tags:
            for (name, value) in tag.items():
                if name == tag_name:
                    return value

        return None

check = IAMPolicyShouldNotUseAction()
