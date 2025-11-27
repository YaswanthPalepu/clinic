# Standard library imports
import json
import logging
import time
from collections import defaultdict
from typing import Awaitable, Callable, Dict, List

# Third party imports
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

logger = logging.getLogger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers"""

    def __init__(
        self, app: ASGIApp, csp_policy: str | None = None, hsts_max_age: int = 31536000
    ) -> None:
        super().__init__(app)
        self.csp_policy = csp_policy
        self.hsts_max_age = hsts_max_age

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        if self.csp_policy:
            response.headers["Content-Security-Policy"] = self.csp_policy

        if request.url.scheme == "https":
            response.headers[
                "Strict-Transport-Security"
            ] = f"max-age={self.hsts_max_age}"

        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware"""

    def __init__(self, app: ASGIApp, requests_per_minute: int = 100) -> None:
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.requests: Dict[str, List[float]] = defaultdict(list)

    def get_client_id(self, request: Request) -> str:
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if request.url.path == "/health":
            response = await call_next(request)
            return response

        current_time = time.time()
        client_id = self.get_client_id(request)

        client_requests = self.requests[client_id]
        recent_requests = [
            req_time for req_time in client_requests if req_time > current_time - 60
        ]

        if len(recent_requests) >= self.requests_per_minute:
            return JSONResponse(
                status_code=429,
                content={"error": "Rate limit exceeded", "retry_after": 60},
            )

        self.requests[client_id].append(current_time)
        response = await call_next(request)

        response.headers["X-RateLimit-Limit"] = str(self.requests_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(
            self.requests_per_minute - len(recent_requests) - 1
        )

        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Request logging middleware"""

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    def get_client_id(self, request: Request) -> str:
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        start_time = time.time()
        request_id = request.headers.get(
            "X-Request-ID", f"req-{int(start_time * 1000)}"
        )

        logger.info(
            json.dumps(
                {
                    "event": "request_started",
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "client_ip": self.get_client_id(request),
                    "timestamp": start_time,
                }
            )
        )

        try:
            response = await call_next(request)

            duration = time.time() - start_time
            logger.info(
                json.dumps(
                    {
                        "event": "request_completed",
                        "request_id": request_id,
                        "status_code": response.status_code,
                        "duration_ms": duration * 1000,
                        "timestamp": time.time(),
                    }
                )
            )

            response.headers["X-Request-ID"] = request_id
            return response

        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                json.dumps(
                    {
                        "event": "request_failed",
                        "request_id": request_id,
                        "error": str(e),
                        "duration_ms": duration * 1000,
                        "timestamp": time.time(),
                    }
                )
            )
            raise


class MetricsMiddleware(BaseHTTPMiddleware):
    """Request metrics middleware"""

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)
        self.request_count = 0
        self.error_count = 0

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        start_time = time.time()

        try:
            response = await call_next(request)

            self.request_count += 1
            duration = time.time() - start_time

            if response.status_code >= 400:
                self.error_count += 1

            response.headers["X-Response-Time"] = f"{duration:.3f}s"
            return response

        except Exception:
            self.request_count += 1
            self.error_count += 1
            raise
