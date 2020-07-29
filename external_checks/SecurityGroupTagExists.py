from AbsObjectTagExists import AbsObjectTagExists


class SecurityGroupTagExists(AbsObjectTagExists):
    def __init__(self):
        super().__init__(check_id='CKV_AWS_998', resource='aws_security_group', tag_name='Owner', case_sensitive=False)


check = SecurityGroupTagExists()
