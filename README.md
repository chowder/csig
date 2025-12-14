# AWS Signature Version 4

A standalone (without `botocore`) Python implementation of the AWS Signature Version 4 (SigV4)

## Overview

SigV4 is an HMAC-SHA256-based request signing protocol that authenticates HTTP requests to AWS services without transmitting secret credentials. The client generates a signature derived from the request content and a date-scoped signing key, which AWS independently verifies.

## Algorithm Specification

The signing process consists of five sequential operations:

### 1. Canonical Request

Construct a normalized representation of the HTTP request. Components are newline-delimited:

```
<HTTP_METHOD>
<CANONICAL_URI>
<CANONICAL_QUERY_STRING>
<CANONICAL_HEADERS>

<SIGNED_HEADERS>
<PAYLOAD_HASH>
```

**Field definitions:**

- `HTTP_METHOD`: HTTP verb (uppercase)
- `CANONICAL_URI`: URL-encoded path, preserving `/`
- `CANONICAL_QUERY_STRING`: Lexicographically sorted, URL-encoded query parameters
- `CANONICAL_HEADERS`: Lowercase header names, sorted alphabetically, format `name:value\n` per header
- Blank line separator
- `SIGNED_HEADERS`: Semicolon-separated list of header names (lowercase, sorted)
- `PAYLOAD_HASH`: SHA256 hex digest of request body

Headers excluded from signing: `user-agent`, `expect`, `transfer-encoding`, `x-amzn-trace-id`

**Example:**

HTTP Request:

```http
GET /my-bucket/documents/report.pdf?max-keys=10&prefix=2024 HTTP/1.1
Host: s3.us-east-1.amazonaws.com
X-Amz-Date: 20240315T093000Z
```

Canonical Request:

```
GET
/my-bucket/documents/report.pdf
max-keys=10&prefix=2024
host:s3.us-east-1.amazonaws.com
x-amz-date:20240315T093000Z

host;x-amz-date
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### 2. String to Sign

Combine signing metadata with the hashed canonical request:

```
AWS4-HMAC-SHA256
<TIMESTAMP>
<CREDENTIAL_SCOPE>
<HASHED_CANONICAL_REQUEST>
```

Where:

- `TIMESTAMP`: ISO8601 format `YYYYMMDDTHHmmssZ` (UTC)
- `CREDENTIAL_SCOPE`: `YYYYMMDD/<region>/<service>/aws4_request`
- `HASHED_CANONICAL_REQUEST`: SHA256 hex digest of canonical request from step 1

### 3. Derive Signing Key

Generate a date/region/service-scoped key through chained HMAC operations. Each operation uses the previous output as the key for the next:

```
k1 = HMAC-SHA256(key: "AWS4" + secret_key, msg: date)
k2 = HMAC-SHA256(key: k1,                  msg: region)
k3 = HMAC-SHA256(key: k2,                  msg: service)
k4 = HMAC-SHA256(key: k3,                  msg: "aws4_request")
signing_key = k4.hexdigest()
```

All intermediate values remain as binary data (32 bytes). Only the final signature in step 4 is hex-encoded.

### 4. Calculate Signature

Apply HMAC-SHA256 using the signing key from step 3 and the string-to-sign from step 2:

```
string_to_sign = """AWS4-HMAC-SHA256
20240315T093000Z
20240315/us-east-1/s3/aws4_request
7c46b8e6d8f5a3b2e1c4d9f0a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9"""

signature = HMAC-SHA256(key: kSigning, msg: string_to_sign).hexdigest()
# => "5a1b2c3d4e5f..."  (64-character hex string)
```

### 5. Construct Authorization Header

Format the signature and metadata into an HTTP header:

```
Authorization: AWS4-HMAC-SHA256 Credential=<ACCESS_KEY>/<CREDENTIAL_SCOPE>, SignedHeaders=<SIGNED_HEADERS>, Signature=<SIGNATURE>
```

Where:

- `CREDENTIAL_SCOPE`: From step 2 (`20240315/us-east-1/s3/aws4_request`)
- `SIGNED_HEADERS`: From step 1 (`host;x-amz-date`)
- `SIGNATURE`: From step 4 (64-character hex string)

**Example:**

```http
GET /my-bucket/documents/report.pdf?max-keys=10&prefix=2024 HTTP/1.1
Host: s3.us-east-1.amazonaws.com
X-Amz-Date: 20240315T093000Z
Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20240315/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=5a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
```

**Additional required headers:**

- `X-Amz-Date`: Timestamp used in signing (ISO8601 UTC format)
- `Host`: Extracted from request URL
- `X-Amz-Security-Token`: Session token (required only for temporary credentials)

---

### Session Tokens

`X-Amz-Security-Token` header is required when using temporary credentials from STS. Temporary credentials consist of three components:

- Access Key (starts with `ASIA`)
- Secret Key
- Session Token

```python
signer = SigV4Signer(
    access_key='ASIAIOSFODNN7EXAMPLE',
    secret_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    region='us-east-1',
    service='s3',
    session_token='AQoDYXdzEJr...'
)
```

### UNSIGNED-PAYLOAD

Requests can optionally use the literal string `UNSIGNED-PAYLOAD` in place of the SHA256 payload hash. 

This is useful for streaming uploads where the full payload isn't available upfront, or when hashing large payloads is undesired.

```python
headers = signer.create_headers(
    method='PUT',
    url='https://my-bucket.s3.us-east-1.amazonaws.com/large-file.bin',
    unsigned_payload=True,
)
```

## Implementation

```python
from sig import SigV4Signer, Service

signer = SigV4Signer(
    access_key='AKIAIOSFODNN7EXAMPLE',
    secret_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    region='us-east-1',
    service=Service.ES
)

headers = signer.create_headers(
    method='GET',
    url='https://search-domain.us-east-1.es.amazonaws.com/_search',
    headers={'Content-Type': 'application/json'},
    body='{"query": {"match_all": {}}}'
)
```

## Summary

SigV4 generates stateless signed tokens similar to JWTs:

- Starting the HMAC chain with the AWS secret key proves the originator
- Any modification invalidates the signature
- Signatures expire after 15 minutes, which is possible because a timestamp forms part of the signature
- Derived key bound to a specific date, region, and service; compromise doesn't enable cross-scope usage
