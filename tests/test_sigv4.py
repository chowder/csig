import json
import unittest
from typing import Any, Dict, Optional, Union

from freezegun import freeze_time
from botocore.auth import SigV4Auth, S3SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

from csig.sigv4 import SigV4Signer, Service

Headers = Dict[str, Any]

FIXED_TIME = '2023-12-15 12:00:00'


class TestSigV4Implementation(unittest.TestCase):
    # Using test credentials from AWS documentation so that we can compare the output at each step against the docs.
    # see: https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
    ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'
    SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    REGION = 'us-east-1'

    @staticmethod
    def _extract_signature(auth_header: Optional[str]) -> Optional[str]:
        if not auth_header:
            return None
        _, _, signature = auth_header.partition('Signature=')
        return signature or None

    def _sign(
            self,
            method: str,
            url: str,
            service: Service,
            headers: Optional[Headers] = None,
            body: Optional[Union[str, bytes]] = None,
            token: Optional[str] = None
    ) -> Headers:
        signer = SigV4Signer(
            self.ACCESS_KEY,
            self.SECRET_KEY,
            self.REGION,
            service,
            token
        )
        return signer.create_headers(method, url, headers or {}, body)

    def _sign_with_botocore(
            self,
            method: str,
            url: str,
            service: Union[str, Service],
            headers: Optional[Headers] = None,
            body: Optional[Union[str, bytes]] = None,
            token: Optional[str] = None
    ) -> Headers:
        service_str = service.value if isinstance(service, Service) else service
        creds = Credentials(self.ACCESS_KEY, self.SECRET_KEY, token)
        req = AWSRequest(method=method, url=url, data=body, headers=headers or {})
        req.context = {}

        # Use S3SigV4Auth for S3, regular SigV4Auth for other services
        if service_str == 's3':
            auth = S3SigV4Auth(creds, service_str, self.REGION)
        else:
            auth = SigV4Auth(creds, service_str, self.REGION)

        auth.add_auth(req)
        return dict(req.headers)

    def _assert_signatures_match(self, actual: Headers, expected: Headers) -> None:
        actual_signature = self._extract_signature(actual.get('Authorization', ''))
        expected_signature = self._extract_signature(expected.get('Authorization', ''))

        self.assertIsNotNone(actual_signature, "Standalone signature is missing")
        self.assertIsNotNone(expected_signature, "Botocore signature is missing")
        self.assertEqual(
            actual_signature,
            expected_signature,
            f"Signatures don't match:\n  Actual: {actual_signature}\n  Expected:   {expected_signature}"
        )

    @freeze_time(FIXED_TIME)
    def test_get_with_query_parameters(self) -> None:
        method = 'GET'
        url = 'https://my-bucket.s3.us-east-1.amazonaws.com/my-file.txt?versionId=abc123&encoding=utf8'

        standalone = self._sign(method, url, Service.S3)
        botocore = self._sign_with_botocore(method, url, Service.S3)

        self._assert_signatures_match(standalone, botocore)

    @freeze_time(FIXED_TIME)
    def test_post_with_session_token(self) -> None:
        method = 'POST'
        url = 'https://dynamodb.us-east-1.amazonaws.com/'
        body = json.dumps({"TableName": "test-table"})
        headers = {
            'Content-Type': 'application/x-amz-json-1.0',
            'X-Amz-Target': 'DynamoDB_20120810.GetItem'
        }
        token = 'AQoDYXdzEJr1234567890EXAMPLE'

        standalone = self._sign(method, url, Service.DYNAMODB, headers.copy(), body, token)
        botocore = self._sign_with_botocore(method, url, Service.DYNAMODB, headers.copy(), body, token)

        self._assert_signatures_match(standalone, botocore)

    @freeze_time(FIXED_TIME)
    def test_empty_body(self) -> None:
        method = 'GET'
        url = 'https://example.lambda.us-east-1.amazonaws.com/prod/items'

        standalone = self._sign(method, url, Service.LAMBDA)
        botocore = self._sign_with_botocore(method, url, Service.LAMBDA)

        self._assert_signatures_match(standalone, botocore)

    @freeze_time(FIXED_TIME)
    def test_headers_excluded_from_signing(self) -> None:
        method = 'GET'
        url = 'https://example.us-east-1.amazonaws.com/test'
        headers = {
            'User-Agent': 'MyClient/1.0',  # Should be excluded
            'Content-Type': 'application/json',  # Should be included
        }

        standalone = self._sign(method, url, Service.IAM, headers.copy())
        botocore = self._sign_with_botocore(method, url, Service.IAM, headers.copy())

        self._assert_signatures_match(standalone, botocore)

    @freeze_time(FIXED_TIME)
    def test_query_string_sorting(self) -> None:
        method = 'GET'
        # unsorted query parameters
        url = 'https://example.us-east-1.amazonaws.com/test?zebra=1&apple=2&banana=3'

        standalone = self._sign(method, url, Service.STS)
        botocore = self._sign_with_botocore(method, url, Service.STS)

        self._assert_signatures_match(standalone, botocore)

    @freeze_time(FIXED_TIME)
    def test_header_value_trimming(self) -> None:
        method = 'GET'
        url = 'https://example.us-east-1.amazonaws.com/test'
        headers = {
            'Content-Type': '  application/json  ',
            'X-Custom-Header': 'value   with   spaces',
        }

        standalone = self._sign(method, url, Service.EC2, headers.copy())
        botocore = self._sign_with_botocore(method, url, Service.EC2, headers.copy())

        self._assert_signatures_match(standalone, botocore)

    @freeze_time(FIXED_TIME)
    def test_ipv6_address_with_custom_port(self) -> None:
        method = 'GET'
        url = 'https://[2001:db8::1]:8443/path'

        standalone = self._sign(method, url, Service.S3)
        botocore = self._sign_with_botocore(method, url, Service.S3)

        self._assert_signatures_match(standalone, botocore)

    @freeze_time(FIXED_TIME)
    def test_ipv6_address_with_default_port(self) -> None:
        method = 'GET'
        url = 'https://[2001:db8::1]:443/path'

        standalone = self._sign(method, url, Service.S3)
        botocore = self._sign_with_botocore(method, url, Service.S3)

        self._assert_signatures_match(standalone, botocore)

    @freeze_time(FIXED_TIME)
    def test_ipv6_address_without_port(self) -> None:
        method = 'GET'
        url = 'https://[2001:db8::1]/path'

        standalone = self._sign(method, url, Service.S3)
        botocore = self._sign_with_botocore(method, url, Service.S3)

        self._assert_signatures_match(standalone, botocore)

    @freeze_time(FIXED_TIME)
    def test_ipv6_localhost_with_port(self) -> None:
        method = 'GET'
        url = 'http://[::1]:8080/test'

        standalone = self._sign(method, url, Service.IAM)
        botocore = self._sign_with_botocore(method, url, Service.IAM)

        self._assert_signatures_match(standalone, botocore)

    @freeze_time(FIXED_TIME)
    def test_regular_hostname_with_custom_port(self) -> None:
        method = 'GET'
        url = 'https://example.com:8443/path'

        standalone = self._sign(method, url, Service.S3)
        botocore = self._sign_with_botocore(method, url, Service.S3)

        self._assert_signatures_match(standalone, botocore)

    @freeze_time(FIXED_TIME)
    def test_regular_hostname_with_default_port(self) -> None:
        method = 'GET'
        url = 'https://example.com:443/path'

        standalone = self._sign(method, url, Service.S3)
        botocore = self._sign_with_botocore(method, url, Service.S3)

        self._assert_signatures_match(standalone, botocore)

    @freeze_time(FIXED_TIME)
    def test_path_with_dot_segments_non_s3(self) -> None:
        method = 'GET'
        url = 'https://example.us-east-1.amazonaws.com/path/./to/./resource'

        standalone = self._sign(method, url, Service.IAM)
        botocore = self._sign_with_botocore(method, url, Service.IAM)

        self._assert_signatures_match(standalone, botocore)

    @freeze_time(FIXED_TIME)
    def test_path_with_parent_segments_non_s3(self) -> None:
        method = 'GET'
        url = 'https://example.us-east-1.amazonaws.com/path/subdir/../resource'

        standalone = self._sign(method, url, Service.IAM)
        botocore = self._sign_with_botocore(method, url, Service.IAM)

        self._assert_signatures_match(standalone, botocore)

    @freeze_time(FIXED_TIME)
    def test_path_with_consecutive_slashes_non_s3(self) -> None:
        method = 'GET'
        url = 'https://example.us-east-1.amazonaws.com/path//to///resource'

        standalone = self._sign(method, url, Service.LAMBDA)
        botocore = self._sign_with_botocore(method, url, Service.LAMBDA)

        self._assert_signatures_match(standalone, botocore)

    @freeze_time(FIXED_TIME)
    def test_path_complex_normalization_non_s3(self) -> None:
        method = 'GET'
        url = 'https://example.us-east-1.amazonaws.com/a//b/./c/../d///e'

        standalone = self._sign(method, url, Service.EC2)
        botocore = self._sign_with_botocore(method, url, Service.EC2)

        self._assert_signatures_match(standalone, botocore)

    @freeze_time(FIXED_TIME)
    def test_s3_path_with_consecutive_slashes(self) -> None:
        method = 'GET'
        url = 'https://my-bucket.s3.us-east-1.amazonaws.com/path//to///object'

        standalone = self._sign(method, url, Service.S3)
        botocore = self._sign_with_botocore(method, url, Service.S3)

        self._assert_signatures_match(standalone, botocore)

    @freeze_time(FIXED_TIME)
    def test_s3_path_with_dots(self) -> None:
        method = 'GET'
        url = 'https://my-bucket.s3.us-east-1.amazonaws.com/folder/./file/../other'

        standalone = self._sign(method, url, Service.S3)
        botocore = self._sign_with_botocore(method, url, Service.S3)

        self._assert_signatures_match(standalone, botocore)

    @freeze_time(FIXED_TIME)
    def test_path_trailing_slash_preserved(self) -> None:
        method = 'GET'
        url = 'https://example.us-east-1.amazonaws.com/path/to/resource/'

        standalone = self._sign(method, url, Service.IAM)
        botocore = self._sign_with_botocore(method, url, Service.IAM)

        self._assert_signatures_match(standalone, botocore)

    @freeze_time(FIXED_TIME)
    def test_path_with_encoded_characters(self) -> None:
        method = 'GET'
        url = 'https://example.us-east-1.amazonaws.com/path/my%20file.txt'

        standalone = self._sign(method, url, Service.IAM)
        botocore = self._sign_with_botocore(method, url, Service.IAM)

        self._assert_signatures_match(standalone, botocore)


if __name__ == '__main__':
    unittest.main(verbosity=2)
