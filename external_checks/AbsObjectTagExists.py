from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class AbsObjectTagExists(BaseResourceCheck):
    def __init__(self, check_id, resource, tag_name, case_sensitive=True):
        an = 'an' if tag_name[0] in 'aeiouAEIOU' else 'a'
        name = f"Ensure every {resource} resource has {an} '{tag_name}' tag"
        supported_resources = [resource]
        categories = [CheckCategories.CONVENTION]
        super().__init__(name=name, id=check_id, categories=categories, supported_resources=supported_resources)
        self.tag_name = tag_name
        self.case_sensitive = case_sensitive

    def scan_resource_conf(self, conf):
        if 'tags' in conf:
            tags = conf['tags']
            if self.get_tag_value(tags):
                return CheckResult.PASSED

        return CheckResult.FAILED

    def get_tag_value(self, tags):
        for tag in tags:
            for (tag_name, tag_value) in tag.items():
                if (self.case_sensitive and self.tag_name == tag_name) or (not self.case_sensitive and self.tag_name.upper() == tag_name.upper()):
                    return tag_value

        return None
