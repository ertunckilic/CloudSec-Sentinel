from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader
import os

ENTERPRISE_API_KEY_NAME = "X-Enterprise-License"
api_key_header = APIKeyHeader(name=ENTERPRISE_API_KEY_NAME, auto_error=False)


def verify_enterprise_license(api_key_header: str = Security(api_key_header)):
    valid_enterprise_key = os.environ.get("ENTERPRISE_LICENSE_KEY")

    if not api_key_header or api_key_header != valid_enterprise_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Enterprise license required. Contact repository owner for commercial licensing.",
        )
    return api_key_header
