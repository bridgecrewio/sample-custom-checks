from AbsObjectTagExists import AbsObjectTagExists


class S3Tagging(AbsObjectTagExists):
    def __init__(self):
        super().__init__(check_id='CKV_AWS_999', resource='aws_s3_bucket', tag_name='Owner', case_sensitive=False)


check = S3Tagging()
