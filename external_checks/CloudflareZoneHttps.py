from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class CloudflareZoneHttps(BaseResourceCheck):
    def __init__(self):
        name = f"Ensure Cloudflare zone always uses HTTPS"
        check_id = 'CKV_CLOUDFLARE_CUSTOM_1'
        categories = [CheckCategories.NETWORKING]
        supported_resources = ['cloudflare_zone_settings_override']
        super().__init__(name=name, id=check_id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        print(conf)

        settings = conf.get('settings')
        if settings and settings[0]:
            https = settings[0].get('always_use_https')
            if https and https[0] == 'on':
                return CheckResult.PASSED

        return CheckResult.FAILED


check = CloudflareZoneHttps()
