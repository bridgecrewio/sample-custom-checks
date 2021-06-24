from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.util.type_forcers import force_list
from checkov.common.util.type_forcers import force_int
from functools import reduce


def ip_to_int(ip_parts: list):
    ip_int = 0
    for i, ip in enumerate(reversed(ip_parts)):
        ip_int += ip << (8 * i)
    return ip_int


def int_to_ip(ip: int) -> list:
    ip_parts = []
    for i in range(0, 4):
        ip_parts.append((ip >> (8 * i)) & 0xff)
    return list(reversed(ip_parts))


def cidr_to_ip_range(cidr):
    start, end = cidr_to_int_range(cidr)
    return int_to_ip(start), int_to_ip(end)


# TODO does not account for weird things like 192.168.100.1/23
def cidr_to_int_range(cidr):
    ip_str, mask_str = cidr.split('/')
    ip_parts = [int(i) for i in ip_str.split('.')]
    ip_int = ip_to_int(ip_parts)
    num = 2 ** (32 - int(mask_str))
    return ip_int, ip_int + num - 1


class SecurityGroupCidrRangeTooLarge(BaseResourceCheck):
    def __init__(self):
        name = "Security group ingress rules cannot allow more than 256 unique addresses"
        id = "CKV_ORG_CUSTOM_003"
        supported_resources = ['aws_security_group', 'aws_security_group_rule']
        categories = [CheckCategories.NETWORKING]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        """
        Looks for configuration at security group ingress rules:
        https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group-ingress.html
        :param conf: aws_security_group configuration
        :return: <CheckResult>
        """
        rule_cidrs = []
        if 'ingress' in conf:  # This means it's an SG resource with ingress block(s)
            ingress_conf = conf['ingress']
            for ingress_rule in ingress_conf:
                ingress_rules = force_list(ingress_rule)
                for rule in ingress_rules:
                    if isinstance(rule, dict):
                        rule_cidrs += force_list(rule.get('cidr_blocks', [[]])[0])

        if 'type' in conf:  # This means it's an SG_rule resource.
            type = force_list(conf['type'])[0]
            if type == 'ingress':
                rule_cidrs += force_list(conf.get('cidr_blocks', [[]])[0])

        print(rule_cidrs)

        # split into int ranges and sort by start of the range
        rule_ranges = sorted(list(map(lambda r: cidr_to_int_range(r), rule_cidrs)), key=lambda r: r[0])

        distinct_ranges = []
        # find distinct IP ranges across all rules
        for rng in rule_ranges:
            start = rng[0]
            end = rng[1]

            # find a range that could overlap
            overlapping_range = None
            for existing_range in distinct_ranges:
                if existing_range[0] <= start <= existing_range[1]:
                    overlapping_range = existing_range
                    break

            if not overlapping_range:
                distinct_ranges.append(list(rng))
            else:
                # if start was within the range but end is after it, extend the range
                # otherwise this range is entirely within the existing range, so do nothing
                if overlapping_range[1] < end:
                    overlapping_range[1] = end

        total_ips = reduce(lambda sum, rng: sum + rng[1] - rng[0] + 1, distinct_ranges, 0)

        return CheckResult.PASSED if total_ips <= 256 else CheckResult.FAILED

check = SecurityGroupCidrRangeTooLarge()
