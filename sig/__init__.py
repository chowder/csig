"""
AWS Signature Version 4 - Standalone Implementation

This package provides a standalone implementation of AWS Signature Version 4
that doesn't depend on botocore for signing operations.
"""

from .sigv4 import SigV4Signer, UNSIGNED_PAYLOAD, Service, Headers

__version__ = "0.1.0"
__all__ = ["SigV4Signer", "UNSIGNED_PAYLOAD", "Service", "Headers"]
