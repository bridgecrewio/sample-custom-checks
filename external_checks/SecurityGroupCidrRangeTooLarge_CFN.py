from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck
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
        supported_resources = ['AWS::EC2::SecurityGroup', 'AWS::EC2::SecurityGroupIngress']
        categories = [CheckCategories.NETWORKING]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        """
        Looks for configuration at security group ingress rules:
        https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group-ingress.html
        :param conf: aws_security_group configuration
        :return: <CheckResult>
        """
        rules = []
        if conf['Type'] == 'AWS::EC2::SecurityGroup':
            if 'Properties' in conf.keys():
                if 'SecurityGroupIngress' in conf['Properties'].keys():
                    rules = conf['Properties']['SecurityGroupIngress']
        elif conf['Type'] == 'AWS::EC2::SecurityGroupIngress':
            if 'Properties' in conf.keys():
                rules = []
                rules.append(conf['Properties'])

        rule_cidrs = [r['CidrIp'] for r in rules if 'CidrIp' in r]

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

check = SecurityGroupCidrRangeTooLarge
