# Standard library imports
import logging
import os
from typing import Optional

# Third party imports
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logger = logging.getLogger(__name__)
security = HTTPBearer(auto_error=False)


class APIKeyAuth:
    """API Key authentication handler"""

    def __init__(self) -> None:
        self.api_keys = self._load_api_keys()

    def _load_api_keys(self) -> set:
        keys_str = os.getenv("API_KEYS", "")
        if not keys_str:
            return set()
        return set(key.strip() for key in keys_str.split(",") if key.strip())

    def verify_key(self, api_key: str) -> bool:
        if not self.api_keys:
            return True
        return api_key in self.api_keys


auth_handler = APIKeyAuth()


async def verify_api_key(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> bool:
    """Verify API key from header or query parameter"""

    if request.url.path in ["/health", "/metrics", "/"]:
        return True

    if not auth_handler.api_keys:
        return True

    api_key = None

    if credentials:
        api_key = credentials.credentials

    if not api_key:
        api_key = request.headers.get("X-API-Key")

    if not api_key:
        api_key = request.query_params.get("api_key")

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="API key required"
        )

    if not auth_handler.verify_key(api_key):
        client_host = request.client.host if request.client else "unknown"
        logger.warning(f"Invalid API key from {client_host}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key"
        )

    return True
