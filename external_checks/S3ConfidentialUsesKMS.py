from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class S3ConfidentialUsesKMS(BaseResourceCheck):
    def __init__(self):
        name = "Ensure 'confidential' and 'highly confidential' buckets use KMS encryption"
        id = "CKV_ORG_CUSTOM_001"
        supported_resources = ['aws_s3_bucket']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):

        # If the tag isn't present or not the given values then this is moot.
        if 'tags' in conf:
            tags = conf['tags']
            if self.get_tag_value('DataClassification', tags) not in ['Confidential', 'Highly confidential']:
                return CheckResult.UNKNOWN
        else:
            return CheckResult.UNKNOWN

        if 'server_side_encryption_configuration' not in conf:
            return CheckResult.FAILED

        # This is for error handling, but if these fail then it's not actually valid TF
        enc_conf = conf['server_side_encryption_configuration'][0]
        if 'rule' not in enc_conf:
            return CheckResult.FAILED

        rule = enc_conf['rule'][0]
        if 'apply_server_side_encryption_by_default' not in rule:
            return CheckResult.PASSED

        default_conf = rule['apply_server_side_encryption_by_default'][0]
        return CheckResult.PASSED if default_conf.get('sse_algorithm') == ['aws:kms'] else CheckResult.FAILED

    def get_tag_value(self, tag_name, tags):
        for tag in tags:
            for (name, value) in tag.items():
                if name == tag_name:
                    return value

        return None

check = S3ConfidentialUsesKMS()
