from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class GenericTagExists(BaseResourceCheck):
    def __init__(self):
        self.tag_name = 'Owner'
        name = f"Ensure every taggable resource has an '{self.tag_name}' tag"
        supported_resources = ['aws_s3_bucket', 'aws_security_group']
        categories = [CheckCategories.CONVENTION]
        super().__init__(name=name, id='CKV_AWS_997', categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'tags' in conf:
            tags = conf['tags']
            if self.get_tag_value(tags):
                return CheckResult.PASSED

        return CheckResult.FAILED

    def get_tag_value(self, tags):
        for tag in tags:
            for (tag_name, tag_value) in tag.items():
                if self.tag_name == tag_name:
                    return tag_value

        return None


check = GenericTagExists()
