import copy
import hashlib
import hmac
import socket
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional, Union
from urllib.parse import urlsplit, quote, parse_qs

Headers = Dict[str, Any]

EMPTY_SHA256_HASH = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
UNSIGNED_PAYLOAD = 'UNSIGNED-PAYLOAD'
SIGV4_TIMESTAMP = '%Y%m%dT%H%M%SZ'

# From: https://github.com/boto/botocore/blob/1.42.9/botocore/auth.py#L64
UNSIGNED_HEADERS = ['expect', 'transfer-encoding', 'user-agent', 'x-amzn-trace-id']


class Service(Enum):
    S3 = 's3'
    ES = 'es'
    DYNAMODB = 'dynamodb'
    EC2 = 'ec2'
    LAMBDA = 'lambda'
    STS = 'sts'
    IAM = 'iam'

    @classmethod
    def from_string(cls, service: str) -> "Service":
        try:
            return cls(service)
        except ValueError:
            valid_services = ', '.join(s.value for s in cls)
            raise ValueError(f"Unknown service '{service}'. Valid services: {valid_services}")


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def _sha256_hash(data: Union[str, bytes]) -> str:
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def _is_ipv6_address(hostname: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6, hostname)
        return True
    except (OSError, ValueError):
        return False


def _host_from_url(url: str) -> str:
    parts = urlsplit(url)
    if parts.hostname is None:
        raise ValueError(f"Invalid URL: missing hostname in '{url}'")

    hostname = parts.hostname.lower()
    is_ipv6 = _is_ipv6_address(hostname)

    # Check if we need to include the port; default HTTP/HTTPS ports are omitted
    # see: https://github.com/boto/botocore/blob/1.42.9/botocore/auth.py#L83-L90
    default_ports = {'http': 80, 'https': 443}
    include_port = parts.port and parts.port != default_ports.get(parts.scheme)

    # IPv6 addresses *always* need brackets in the Host header
    # see: https://github.com/boto/botocore/blob/1.42.9/botocore/auth.py#L81-L82
    if is_ipv6:
        hostname = f'[{hostname}]'
    if include_port:
        hostname = f'{hostname}:{parts.port}'

    return hostname


def _remove_dot_segments(path: str) -> str:
    # see: https://github.com/boto/botocore/blob/1.42.9/botocore/utils.py#L297-L321
    if not path:
        return ''

    segments = path.split('/')
    result = []

    for segment in segments:
        # Skip empty segments (consecutive slashes) and '.' segments
        if segment and segment != '.':
            if segment == '..':
                # Remove parent directory if present
                if result:
                    result.pop()
            else:
                result.append(segment)

    # Preserve leading slash
    prefix = '/' if path[0] == '/' else ''
    # Preserve trailing slash
    suffix = '/' if path[-1] == '/' and result else ''

    return prefix + '/'.join(result) + suffix


def _normalize_url_path(path: Optional[str], service: Optional[Service] = None) -> str:
    if not path:
        return '/'

    # S3 uses object keys literally without normalization; path is expected to already be properly encoded
    # see: https://github.com/boto/botocore/blob/1.42.9/botocore/auth.py#L531-L533
    if service == Service.S3:
        return path

    # For other services, normalize then quote
    # see: https://github.com/boto/botocore/blob/1.42.9/botocore/auth.py#L378-L380
    normalized = _remove_dot_segments(path)
    return quote(normalized, safe='/~')


def _canonical_query_string(url: str) -> str:
    parts = urlsplit(url)
    if not parts.query:
        return ''

    queries = []
    for key, values in parse_qs(parts.query, keep_blank_values=True).items():
        for value in values:
            encoded_key = quote(key, safe='-_.~')
            encoded_value = quote(value, safe='-_.~')
            queries.append((encoded_key, encoded_value))

    queries.sort()

    return '&'.join(f'{k}={v}' for k, v in queries)


def _canonical_headers(headers: Headers) -> str:
    canonical = {}
    for header, value in headers.items():
        h = header.lower()
        if h not in UNSIGNED_HEADERS:
            canonical[h] = ' '.join(str(value).split())

    sorted_headers = sorted(canonical.items())
    return '\n'.join(f'{k}:{v}' for k, v in sorted_headers)


def _signed_headers(headers: Headers) -> str:
    header_names = [
        header.lower()
        for header in headers.keys()
        if header.lower() not in UNSIGNED_HEADERS
    ]
    return ';'.join(sorted(set(header_names)))


def _canonical_request(
        method: str,
        url: str,
        headers: Headers,
        payload_hash: str,
        service: Optional[Service] = None
) -> str:
    parts = urlsplit(url)

    canonical = [
        method.upper(),
        _normalize_url_path(parts.path, service),
        _canonical_query_string(url),
        _canonical_headers(headers),
        '',
        _signed_headers(headers),
        payload_hash
    ]

    return '\n'.join(canonical)


def _credential_scope(timestamp: datetime, region: str, service: Service) -> str:
    date = timestamp.strftime('%Y%m%d')
    return f'{date}/{region}/{service.value}/aws4_request'


def _string_to_sign(timestamp: datetime, region: str, service: Service, canonical_request: str) -> str:
    return '\n'.join([
        'AWS4-HMAC-SHA256',
        timestamp.strftime(SIGV4_TIMESTAMP),
        _credential_scope(timestamp, region, service),
        _sha256_hash(canonical_request)
    ])


def _create_signing_key(secret_key: str, timestamp: datetime, region: str, service: Service) -> bytes:
    # Derive the signing key by HMAC chaining the contents of:
    #   AWS_SECRET_KEY -> date -> region -> service -> "aws4_request"
    date = timestamp.strftime('%Y%m%d')
    k_date = _sign(f'AWS4{secret_key}'.encode(), date)
    k_region = _sign(k_date, region)
    k_service = _sign(k_region, service.value)
    k_signing = _sign(k_service, 'aws4_request')
    return k_signing


def _authorization_header(
        access_key: str,
        timestamp: datetime,
        region: str,
        service: Service,
        headers: Headers,
        signature: str
) -> str:
    credential = f'{access_key}/{_credential_scope(timestamp, region, service)}'
    signed_headers = _signed_headers(headers)

    return (
        f'AWS4-HMAC-SHA256 '
        f'Credential={credential}, '
        f'SignedHeaders={signed_headers}, '
        f'Signature={signature}'
    )


class SigV4Signer:
    """
    AWS Signature Version 4 request signer.

    Example usage:
        signer = SigV4Signer(
            access_key='AKIAIOSFODNN7EXAMPLE',
            secret_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            region='us-east-1',
            service=Service.ES
        )

        headers = signer.create_headers(
            method='PUT',
            url='https://example.amazonaws.com/path?query=value',
            headers={'Content-Type': 'application/json'},
            body='{"key": "value"}'
        )
    """

    def __init__(
            self,
            access_key: str,
            secret_key: str,
            region: str,
            service: Service,
            session_token: Optional[str] = None
    ) -> None:
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region
        self.session_token = session_token
        self.service = service

    def create_headers(
            self,
            method: str,
            url: str,
            headers: Optional[Headers] = None,
            body: Optional[Union[str, bytes]] = None,
            unsigned_payload: bool = False
    ) -> Headers:
        """
        Create signed headers for an AWS request.

        Args:
            method: HTTP method (GET, POST, PUT, etc.)
            url: Full URL including scheme, host, path, and query string
            headers: Dict of HTTP headers to include in signing (input is not modified)
            body: Request body (str or bytes)
            unsigned_payload: Use UNSIGNED-PAYLOAD instead of hashing body (S3/HTTPS only)

        Returns:
            Dict of headers including the Authorization header and input headers
        """
        headers = copy.deepcopy(headers) if headers else {}
        timestamp = datetime.now(timezone.utc)

        headers['X-Amz-Date'] = timestamp.strftime(SIGV4_TIMESTAMP)

        if 'host' not in {k.lower() for k in headers.keys()}:
            headers['Host'] = _host_from_url(url)

        if self.session_token:
            headers['X-Amz-Security-Token'] = self.session_token

        if unsigned_payload:
            payload_hash = UNSIGNED_PAYLOAD
        elif body is None:
            payload_hash = EMPTY_SHA256_HASH
        else:
            payload_hash = _sha256_hash(body)

        # S3 requires the `X-Amz-Content-SHA256` header as part of signing
        # see: https://github.com/boto/botocore/blob/1.42.9/botocore/auth.py#L483-L488
        if self.service == Service.S3:
            headers['X-Amz-Content-SHA256'] = payload_hash

        canonical_req = _canonical_request(method, url, headers, payload_hash, self.service)

        string_to_sign = _string_to_sign(timestamp, self.region, self.service, canonical_req)

        signing_key = _create_signing_key(self.secret_key, timestamp, self.region, self.service)
        signature = _sign(signing_key, string_to_sign).hex()

        headers['Authorization'] = _authorization_header(
            self.access_key, timestamp, self.region, self.service, headers, signature
        )

        return headers
